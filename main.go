package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/zeebo/xxh3"
	"go4.org/netipx"
	"golang.org/x/net/idna"
)

const (
	uaStr                  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	minRelevanceDomains    = 500_000
	maxSafeDomains         = 299_000
	maxCloudflareLists     = 299
	maxLabelPurgeAttempts  = 10
	unrankedRank           = uint32(math.MaxUint32)
	coreRankProtectionCap  = 10_000
	cacheMagicV3           = "RELCAC03"
	spamAllowRuleName      = "Allow: Spam Exceptions"
	dummyTrafficExpression = `any(dns.domains[*] in {"invalid.local.blocklist.temp"})`
)

var (
	defaultProtectedRules = []string{
		"IoT Bypass", "Custom", "Keywords", "SafeSearch",
		"Global Blocklist", "Global Bypass", "Block IoT Network", "YouTube Restricted",
	}
	defaultTopLists = []struct {
		URL, Compression string
		Col              int
		SkipHeader       bool
	}{
		{"https://tranco-list.eu/top-1m.csv.zip", "zip", 1, false},
		{"https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", "gzip", 0, true},
		{"https://downloads.majestic.com/majestic_million.csv", "raw", 2, true},
		{"https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip", "zip", 1, true},
		{"https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", "zip", 1, false},
	}
	rejectedEntryRe = regexp.MustCompile(`invalid (?:label|domain|value) ["']?([a-zA-Z0-9_\-\.:/]+?)["'\s]`)
)

func logInfo(f string, a ...any) { fmt.Printf("[INFO] "+f+"\n", a...) }
func logWarn(f string, a ...any) { fmt.Fprintf(os.Stderr, "[WARN] "+f+"\n", a...) }
func logErr(f string, a ...any)  { fmt.Fprintf(os.Stderr, "[ERROR] "+f+"\n", a...) }

func ptrOr[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

func jitterMs(maxMs int64) time.Duration {
	if maxMs <= 1 {
		return 0
	}
	return time.Duration(rand.Int64N(maxMs)) * time.Millisecond
}

func divCeil(n, d int) int {
	if n <= 0 {
		return 0
	}
	return (n + d - 1) / d
}

// ---------- Configuration ----------

type settingsConfig struct {
	MaxWorkers               *int     `toml:"max_workers"`
	MaxListSize              *int     `toml:"max_list_size"`
	TotalQuota               *int     `toml:"total_quota"`
	RequestTimeout           any      `toml:"request_timeout"`
	ScrubTargets             []string `toml:"scrub_targets"`
	AutoEnableRules          *bool    `toml:"auto_enable_rules"`
	BlockPageEnabled         *bool    `toml:"block_page_enabled"`
	BaseFeed                 string   `toml:"base_feed"`
	ProtectedRules           []string `toml:"protected_rules"`
	UnmanagedListKeywords    []string `toml:"unmanaged_list_keywords"`
	NeverBlock               []string `toml:"never_block"`
	RelevanceCacheDir        string   `toml:"relevance_cache_dir"`
	RelevanceMinRefreshHours *int64   `toml:"relevance_min_refresh_hours"`
	RelevanceTTLDays         *int64   `toml:"relevance_ttl_days"`
}

type policyConfig struct {
	Prefix             string   `toml:"prefix"`
	Name               string   `toml:"name"`
	Type               string   `toml:"type"`
	Action             string   `toml:"action"`
	Priority           *int     `toml:"priority"`
	Trimmable          *bool    `toml:"trimmable"`
	Include            []string `toml:"include"`
	Exclude            []string `toml:"exclude"`
	UseSpamTLD         bool     `toml:"use_spam_tld"`
	RestrictUsers      bool     `toml:"restrict_users"`
	IdentityCondition  string   `toml:"identity_condition"`
	Enabled            *bool    `toml:"enabled"`
	BlockPageEnabled   *bool    `toml:"block_page_enabled"`
	IPCategories       bool     `toml:"ip_categories"`
	SecurityCategories []any    `toml:"security_categories"`
	ContentCategories  []any    `toml:"content_categories"`
	AppIDs             []any    `toml:"app_ids"`
	Domains            []string `toml:"domains"`
}

func (p policyConfig) resolvedType() string {
	if p.Type == "" {
		return "DOMAIN"
	}
	return strings.ToUpper(p.Type)
}

func (p policyConfig) resolvedAction() string {
	if p.Action == "" {
		return "block"
	}
	return p.Action
}

func (p policyConfig) effectiveIdentity(cfg *appConfig) string {
	if p.RestrictUsers {
		return cfg.TargetIdentity
	}
	return strings.TrimSpace(p.IdentityCondition)
}

func (p policyConfig) isScoped(cfg *appConfig) bool { return p.effectiveIdentity(cfg) != "" }

func (p policyConfig) isTrimmable() bool {
	if p.resolvedAction() == "allow" || p.resolvedType() == "IP" {
		return false
	}
	if p.Trimmable != nil {
		return *p.Trimmable
	}
	full := strings.ToLower(p.Name + " " + p.Prefix + " " + strings.Join(p.Include, " "))
	for _, kw := range []string{"porn", "nsfw", "adult", "malware", "tif", "threat", "badware"} {
		if strings.Contains(full, kw) {
			return true
		}
	}
	return false
}

func (p policyConfig) resolvedPriority(cfg *appConfig) int {
	if p.Priority != nil {
		return *p.Priority
	}
	if p.resolvedAction() == "allow" {
		return 0
	}
	if p.resolvedType() == "IP" {
		return 50
	}
	key := strings.ToLower(p.Name + " " + p.Prefix)
	switch {
	case strings.Contains(key, "bypass"):
		return 10
	case strings.Contains(key, "normal") || strings.Contains(key, "relaxed") ||
		strings.Contains(key, "base") || slices.Contains(p.Include, cfg.BaseFeed):
		return 20
	case strings.Contains(key, "restrictive") || strings.Contains(key, "pro") || strings.Contains(key, "adblock"):
		return 25
	case strings.Contains(key, "social") || strings.Contains(key, "ai"):
		return 30
	case strings.Contains(key, "piracy"):
		return 40
	case strings.Contains(key, "malware") || strings.Contains(key, "tif") ||
		strings.Contains(key, "threat") || strings.Contains(key, "phish"):
		return 80
	case strings.Contains(key, "badware"):
		return 85
	case strings.Contains(key, "porn") || strings.Contains(key, "nsfw") || strings.Contains(key, "adult"):
		return 90
	default:
		return 60
	}
}

func (p policyConfig) clone() policyConfig {
	p.Include = slices.Clone(p.Include)
	p.Exclude = slices.Clone(p.Exclude)
	p.Domains = slices.Clone(p.Domains)
	p.SecurityCategories = slices.Clone(p.SecurityCategories)
	p.ContentCategories = slices.Clone(p.ContentCategories)
	p.AppIDs = slices.Clone(p.AppIDs)
	return p
}

type rawConfig struct {
	Settings        settingsConfig                    `toml:"settings"`
	Sources         map[string]any                    `toml:"sources"`
	IPSources       map[string]any                    `toml:"ip_sources"`
	Policies        map[string]policyConfig           `toml:"policies"`
	TLD             struct{ URL string `toml:"url"` } `toml:"tld"`
	SpamAllowSource *struct {
		Name      string `toml:"name"`
		URL       string `toml:"url"`
		Relevance *bool  `toml:"relevance"`
	} `toml:"spam_allow_source"`
	GatewayPolicies map[string]any `toml:"gateway_policies"`
}

type appConfig struct {
	APIToken, AccountID, TargetIdentity, BaseFeed, RelevanceCacheDir string
	MaxWorkers, MaxListSize, TotalQuota                              int
	Timeout                                                          time.Duration
	ScrubTargets, UnmanagedListKeywords                              []string
	AutoEnableRules, BlockPageEnabled                                bool
	ForceRefreshRelevance, StrictFeeds                               bool
	ProtectedRules, NeverBlock                                       map[string]struct{}
	RelevanceMinRefreshSecs, RelevanceTTLSecs                        int64
	Raw                                                              rawConfig
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func (c *appConfig) isManagedList(name string) bool {
	return containsAny(name, c.ScrubTargets) && !containsAny(name, c.UnmanagedListKeywords)
}

func (c *appConfig) isProtectedRule(name string) bool {
	if _, ok := c.ProtectedRules[name]; ok {
		return true
	}
	for k := range c.ProtectedRules {
		if strings.Contains(name, k) {
			return true
		}
	}
	return false
}

func (c *appConfig) isNeverBlocked(domain string) bool {
	if len(c.NeverBlock) == 0 {
		return false
	}
	if _, ok := c.NeverBlock[domain]; ok {
		return true
	}
	if trimmed, ok := strings.CutPrefix(domain, "www."); ok {
		_, found := c.NeverBlock[trimmed]
		return found
	}
	return false
}

func parseTimeoutSecs(v any) int64 {
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		v = arr[len(arr)-1]
	}
	switch val := v.(type) {
	case int64:
		return max(val, 5)
	case float64:
		return max(int64(val), 5)
	default:
		return 30
	}
}

func loadConfig(configPath string, forceRefresh, strict bool) (*appConfig, error) {
	var raw rawConfig
	if _, err := toml.DecodeFile(configPath, &raw); err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", configPath, err)
	}

	apiToken := strings.TrimSpace(os.Getenv("API_TOKEN"))
	accountID := strings.TrimSpace(os.Getenv("ACCOUNT_ID"))
	if apiToken == "" || accountID == "" {
		return nil, errors.New("missing API_TOKEN or ACCOUNT_ID in environment")
	}

	var excluded []string
	for _, rawEmail := range append(
		[]string{os.Getenv("SECONDARY_EMAIL"), os.Getenv("TERTIARY_EMAIL")},
		strings.Split(os.Getenv("EXCLUDED_EMAILS"), ",")...,
	) {
		if e := strings.TrimSpace(rawEmail); e != "" {
			if q := fmt.Sprintf(`"%s"`, e); !slices.Contains(excluded, q) {
				excluded = append(excluded, q)
			}
		}
	}
	targetIdentity := ""
	if len(excluded) > 0 {
		targetIdentity = fmt.Sprintf("not(identity.email in {%s})", strings.Join(excluded, " "))
	}

	s := raw.Settings
	protList := s.ProtectedRules
	if len(protList) == 0 {
		protList = defaultProtectedRules
	}
	protected := make(map[string]struct{}, len(protList)+len(raw.GatewayPolicies))
	for _, r := range protList {
		protected[r] = struct{}{}
	}
	for k := range raw.GatewayPolicies {
		protected[k] = struct{}{}
	}

	unmanaged := s.UnmanagedListKeywords
	if len(unmanaged) == 0 {
		unmanaged = []string{"IoT Bypass"}
	}

	neverBlock := make(map[string]struct{}, len(s.NeverBlock))
	for _, d := range s.NeverBlock {
		if clean, ok := normalizeDomainBytes([]byte(d), nil); ok {
			neverBlock[string(clean)] = struct{}{}
		}
	}

	cacheDir := strings.TrimSpace(os.Getenv("RELEVANCE_CACHE_DIR"))
	if cacheDir == "" {
		cacheDir = strings.TrimSpace(s.RelevanceCacheDir)
	}
	if cacheDir == "" {
		cacheDir = filepath.Join(".cache", "relevance")
	}
	baseFeed := s.BaseFeed
	if baseFeed == "" {
		baseFeed = "HaGeZi Normal"
	}

	return &appConfig{
		APIToken:                apiToken,
		AccountID:               accountID,
		TargetIdentity:          targetIdentity,
		MaxWorkers:              max(ptrOr(s.MaxWorkers, 8), 1),
		MaxListSize:             max(ptrOr(s.MaxListSize, 1000), 1),
		TotalQuota:              min(max(ptrOr(s.TotalQuota, maxSafeDomains), 1), maxSafeDomains),
		Timeout:                 time.Duration(parseTimeoutSecs(s.RequestTimeout)) * time.Second,
		ScrubTargets:            s.ScrubTargets,
		AutoEnableRules:         ptrOr(s.AutoEnableRules, true),
		BlockPageEnabled:        ptrOr(s.BlockPageEnabled, false),
		BaseFeed:                baseFeed,
		ProtectedRules:          protected,
		UnmanagedListKeywords:   unmanaged,
		NeverBlock:              neverBlock,
		RelevanceCacheDir:       cacheDir,
		RelevanceMinRefreshSecs: max(ptrOr(s.RelevanceMinRefreshHours, 24), 0) * 3600,
		RelevanceTTLSecs:        max(ptrOr(s.RelevanceTTLDays, 7), 1) * 86400,
		ForceRefreshRelevance:   forceRefresh,
		StrictFeeds:             strict,
		Raw:                     raw,
	}, nil
}

// ---------- Cloudflare API Client ----------

type gatewayList struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Count       *int64 `json:"count"`
}

type gatewayRule struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Action        string          `json:"action"`
	Enabled       bool            `json:"enabled"`
	Traffic       string          `json:"traffic"`
	Identity      string          `json:"identity"`
	Filters       []string        `json:"filters"`
	RuleSettings  map[string]any  `json:"rule_settings"`
	DevicePosture json.RawMessage `json:"device_posture"`
	Schedule      json.RawMessage `json:"schedule"`
	Precedence    json.RawMessage `json:"precedence"`
	Description   json.RawMessage `json:"description"`
}

func (r gatewayRule) isDNSRule() bool {
	return len(r.Filters) == 0 || slices.Contains(r.Filters, "dns")
}

func (r gatewayRule) clone() gatewayRule {
	r.Filters = slices.Clone(r.Filters)
	if r.RuleSettings != nil {
		cp := make(map[string]any, len(r.RuleSettings))
		for k, v := range r.RuleSettings {
			cp[k] = v
		}
		r.RuleSettings = cp
	}
	return r
}

type cfEnvelope struct {
	Success    *bool           `json:"success"`
	Result     json.RawMessage `json:"result"`
	Errors     json.RawMessage `json:"errors"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type listItem struct {
	Value string `json:"value"`
}

func isNonNullRaw(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

func parseRulePrecedence(raw json.RawMessage) (int64, bool) {
	if !isNonNullRaw(raw) {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int64(f), true
	}
	return 0, false
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

type cloudflareAPI struct {
	client      *http.Client
	baseURL     string
	token       string
	mu          sync.Mutex
	nextWriteAt time.Time
}

func newCloudflareAPI(cfg *appConfig) *cloudflareAPI {
	return &cloudflareAPI{
		client:      newHTTPClient(cfg.Timeout),
		baseURL:     fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/gateway", cfg.AccountID),
		token:       cfg.APIToken,
		nextWriteAt: time.Now(),
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (cf *cloudflareAPI) paceWrite(ctx context.Context) error {
	cf.mu.Lock()
	target := cf.nextWriteAt
	if now := time.Now(); now.After(target) {
		target = now
	}
	cf.nextWriteAt = target.Add(220*time.Millisecond + jitterMs(60))
	cf.mu.Unlock()
	if wait := time.Until(target); wait > 0 {
		return sleepWithContext(ctx, wait)
	}
	return nil
}

func (cf *cloudflareAPI) backoffAllWriters(wait time.Duration) {
	cf.mu.Lock()
	if resume := time.Now().Add(wait); resume.After(cf.nextWriteAt) {
		cf.nextWriteAt = resume
	}
	cf.mu.Unlock()
}

func (cf *cloudflareAPI) req(ctx context.Context, method, endpoint string, body any) (*cfEnvelope, error) {
	url := cf.baseURL + "/" + endpoint
	const retries = 6

	var bodyBytes []byte
	if body != nil {
		var err error
		if bodyBytes, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("marshal body for %s %s: %w", method, endpoint, err)
		}
	}

	retryWait := func(attempt int, msg string) error {
		wait := time.Duration(min(2*(1<<attempt), 60))*time.Second + jitterMs(1000)
		logWarn("%s on %s %s. Retrying in %.2fs...", msg, method, endpoint, wait.Seconds())
		return sleepWithContext(ctx, wait)
	}

	for attempt := 0; attempt < retries; attempt++ {
		if method != http.MethodGet {
			if err := cf.paceWrite(ctx); err != nil {
				return nil, err
			}
		}

		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		httpReq, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("User-Agent", uaStr)
		httpReq.Header.Set("Authorization", "Bearer "+cf.token)
		if bodyBytes != nil {
			httpReq.Header.Set("Content-Type", "application/json")
		}

		resp, err := cf.client.Do(httpReq)
		if err != nil {
			if ctx.Err() != nil || attempt == retries-1 {
				return nil, err
			}
			if err := retryWait(attempt, fmt.Sprintf("Network error (%v)", err)); err != nil {
				return nil, err
			}
			continue
		}

		respBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			if attempt == retries-1 {
				return nil, readErr
			}
			if err := retryWait(attempt, fmt.Sprintf("Body read error (%v)", readErr)); err != nil {
				return nil, err
			}
			continue
		}

		code := resp.StatusCode
		if code == http.StatusTooManyRequests && attempt < retries-1 {
			waitSecs := 2 * (1 << attempt)
			if parsed, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil {
				waitSecs = parsed
			}
			wait := time.Duration(min(max(waitSecs, 1), 120))*time.Second + jitterMs(1000)
			cf.backoffAllWriters(wait)
			logWarn("Rate limited (429) on %s %s. Backing off all writers for %.2fs.", method, endpoint, wait.Seconds())
			if err := sleepWithContext(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}

		if (code == 408 || (code >= 500 && code <= 504) || (code >= 520 && code <= 530)) && attempt < retries-1 {
			if err := retryWait(attempt, fmt.Sprintf("Transient HTTP %d", code)); err != nil {
				return nil, err
			}
			continue
		}

		if code < 200 || code >= 300 {
			logErr("Cloudflare API error [%d] on %s %s: %s", code, method, endpoint, string(respBytes))
			return nil, fmt.Errorf("HTTP %d on %s %s: %s", code, method, endpoint, string(respBytes))
		}

		var env cfEnvelope
		if err := json.Unmarshal(respBytes, &env); err != nil {
			return nil, fmt.Errorf("invalid JSON from %s %s: %w", method, endpoint, err)
		}
		if env.Success != nil && !*env.Success {
			logErr("Cloudflare API error payload on %s %s: %s", method, endpoint, string(env.Errors))
			return nil, fmt.Errorf("Cloudflare API failed on %s: %s", endpoint, string(env.Errors))
		}
		return &env, nil
	}
	return nil, fmt.Errorf("exceeded max retries on %s", endpoint)
}

func paginate[T any](cf *cloudflareAPI, endpoint string) ([]T, error) {
	fetchPage := func(ctx context.Context, page int) ([]T, int, error) {
		env, err := cf.req(ctx, http.MethodGet, fmt.Sprintf("%s?page=%d&per_page=100", endpoint, page), nil)
		if err != nil {
			return nil, 0, err
		}
		var items []T
		if isNonNullRaw(env.Result) {
			if err := json.Unmarshal(env.Result, &items); err != nil {
				return nil, 0, fmt.Errorf("deserialize %s page %d: %w", endpoint, page, err)
			}
		}
		return items, max(env.ResultInfo.TotalPages, 1), nil
	}

	first, totalPages, err := fetchPage(context.Background(), 1)
	if err != nil || totalPages == 1 {
		return first, err
	}

	pages := make([][]T, totalPages)
	pages[0] = first
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for page := 2; page <= totalPages; page++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			items, _, pErr := fetchPage(ctx, p)
			if pErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = pErr
					cancel()
				}
				errMu.Unlock()
				return
			}
			pages[p-1] = items
		}(page)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	totalLen := 0
	for _, p := range pages {
		totalLen += len(p)
	}
	out := make([]T, 0, totalLen)
	for _, p := range pages {
		out = append(out, p...)
	}
	return out, nil
}

func (cf *cloudflareAPI) getLists() ([]gatewayList, error) { return paginate[gatewayList](cf, "lists") }
func (cf *cloudflareAPI) getRules() ([]gatewayRule, error) { return paginate[gatewayRule](cf, "rules") }

func (cf *cloudflareAPI) deleteList(id string) error {
	_, err := cf.req(context.Background(), http.MethodDelete, "lists/"+id, nil)
	return err
}

func (cf *cloudflareAPI) deleteRule(id string) error {
	_, err := cf.req(context.Background(), http.MethodDelete, "rules/"+id, nil)
	return err
}

func wrapListItems(items []string) []listItem {
	out := make([]listItem, len(items))
	for i, v := range items {
		out[i] = listItem{Value: v}
	}
	return out
}

func (cf *cloudflareAPI) createList(ctx context.Context, name string, items []string, listType, desc string) (string, error) {
	env, err := cf.req(ctx, http.MethodPost, "lists", map[string]any{
		"name": name, "type": listType, "items": wrapListItems(items), "description": desc,
	})
	if err != nil {
		return "", err
	}
	var created struct{ ID string `json:"id"` }
	if err := json.Unmarshal(env.Result, &created); err != nil || created.ID == "" {
		return "", fmt.Errorf("createList missing result.id for '%s'", name)
	}
	return created.ID, nil
}

func (cf *cloudflareAPI) updateList(ctx context.Context, id, name string, items []string, desc string) error {
	_, err := cf.req(ctx, http.MethodPut, "lists/"+id, map[string]any{
		"name": name, "items": wrapListItems(items), "description": desc,
	})
	return err
}

func (cf *cloudflareAPI) upsertRule(method, endpoint string, payload map[string]any) (*gatewayRule, error) {
	settings, _ := payload["rule_settings"].(map[string]any)
	if settings == nil {
		settings = map[string]any{}
		payload["rule_settings"] = settings
	}
	if _, exists := settings["block_page_enabled"]; !exists {
		settings["block_page_enabled"] = false
	}
	env, err := cf.req(context.Background(), method, endpoint, payload)
	if err != nil || !isNonNullRaw(env.Result) {
		return nil, err
	}
	var r gatewayRule
	if err := json.Unmarshal(env.Result, &r); err != nil {
		return nil, fmt.Errorf("deserialize rule: %w", err)
	}
	return &r, nil
}

func (cf *cloudflareAPI) createRule(payload map[string]any) (*gatewayRule, error) {
	return cf.upsertRule(http.MethodPost, "rules", payload)
}

func (cf *cloudflareAPI) updateRule(id string, payload map[string]any) (*gatewayRule, error) {
	return cf.upsertRule(http.MethodPut, "rules/"+id, payload)
}

// ---------- Single-Pass Zero-Alloc Domain Validation & Parsing ----------

func stripWWWBytes(b []byte) []byte {
	if len(b) > 4 && bytes.HasPrefix(b, []byte("www.")) && bytes.IndexByte(b[4:], '.') >= 0 {
		return b[4:]
	}
	return b
}

func normalizeDomainBytes(raw []byte, scratch *[]byte) ([]byte, bool) {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return nil, false
	}

	// Single-pass zero-alloc fast path for clean lowercase ASCII domains
	if len(b) >= 4 && len(b) <= 253 {
		lblStart, labels, lastAlpha, ok := 0, 0, true, true
		for i, c := range b {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
				lastAlpha = false
			case c == '-':
				lastAlpha = false
				if i == lblStart || b[i-1] == '-' {
					ok = false
				}
			case c == '.':
				if n := i - lblStart; n == 0 || n > 63 || b[i-1] == '-' {
					ok = false
				} else {
					labels++
					lblStart = i + 1
					lastAlpha = true
				}
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && labels >= 1 && lastAlpha {
			if n := len(b) - lblStart; n >= 2 && n <= 63 && b[len(b)-1] != '-' {
				return b, true
			}
		}
	}

	// Slow path: URL stripping, wildcards, uppercase ASCII, IDNA, punycode
	if idx := bytes.Index(b, []byte("://")); idx >= 0 {
		b = b[idx+3:]
	}
	if idx := bytes.IndexAny(b, "?/:"); idx >= 0 {
		b = b[:idx]
	}
	b = bytes.Trim(bytes.TrimPrefix(b, []byte("*.")), ".")
	if len(b) == 0 || len(b) > 253 || bytes.IndexByte(b, '.') < 0 || bytes.Contains(b, []byte("..")) {
		return nil, false
	}

	hasUpper, nonASCII := false, false
	for _, c := range b {
		if c >= 0x80 {
			nonASCII = true
			break
		}
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
	}

	d := b
	if nonASCII {
		ascii, err := idna.Lookup.ToASCII(strings.ToLower(string(b)))
		if err != nil || len(ascii) > 253 {
			return nil, false
		}
		d = []byte(ascii)
	} else if hasUpper {
		var buf []byte
		if scratch != nil && cap(*scratch) >= len(b) {
			buf = (*scratch)[:len(b)]
		} else {
			buf = make([]byte, len(b))
		}
		for i, c := range b {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf[i] = c
		}
		if scratch != nil {
			*scratch = buf
		}
		d = buf
	}

	labels := 0
	var last []byte
	for rest := d; ; {
		dot := bytes.IndexByte(rest, '.')
		lbl := rest
		if dot >= 0 {
			lbl = rest[:dot]
		}
		n := len(lbl)
		if n == 0 || n > 63 || lbl[0] == '-' || lbl[n-1] == '-' {
			return nil, false
		}
		for _, c := range lbl {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return nil, false
			}
		}
		if n >= 4 && lbl[2] == '-' && lbl[3] == '-' {
			if !bytes.HasPrefix(lbl, []byte("xn--")) {
				return nil, false
			}
			if _, err := idna.Lookup.ToUnicode(string(lbl)); err != nil {
				return nil, false
			}
		}
		labels++
		last = lbl
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	if labels < 2 || len(last) < 2 {
		return nil, false
	}
	if !bytes.HasPrefix(last, []byte("xn--")) {
		for _, c := range last {
			if c < 'a' || c > 'z' {
				return nil, false
			}
		}
	} else if len(last) < 5 {
		return nil, false
	}
	return d, true
}

func hasParentDomain[V any](host string, lookup map[string]V) bool {
	for rest := host; ; {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return false
		}
		parent := rest[dot+1:]
		if strings.IndexByte(parent, '.') < 0 {
			return false
		}
		if _, ok := lookup[parent]; ok {
			return true
		}
		rest = parent
	}
}

func hasSuffixDomain[V any](host string, lookup map[string]V) bool {
	if _, ok := lookup[host]; ok {
		return true
	}
	return hasParentDomain(host, lookup)
}

// ---------- Rank-Aware Relevance Set, Radix Index & Binary Cache (RELCAC03) ----------

type rankedHash struct {
	hash uint64
	rank uint32
}

type relevanceSet struct {
	hashes  []uint64
	ranks   []uint32
	offsets [65537]uint32
}

func (rs *relevanceSet) buildIndex() {
	n := uint32(len(rs.hashes))
	var cur uint32
	for i, h := range rs.hashes {
		for b := uint32(h >> 48); cur <= b; cur++ {
			rs.offsets[cur] = uint32(i)
		}
	}
	for ; cur <= 65536; cur++ {
		rs.offsets[cur] = n
	}
}

func (rs *relevanceSet) len() int {
	if rs == nil {
		return 0
	}
	return len(rs.hashes)
}

func (rs *relevanceSet) lookupHash(h uint64) (uint32, bool) {
	b := h >> 48
	lo, hi := rs.offsets[b], rs.offsets[b+1]
	if lo == hi {
		return 0, false
	}
	if idx, ok := slices.BinarySearch(rs.hashes[lo:hi], h); ok {
		return rs.ranks[lo+uint32(idx)], true
	}
	return 0, false
}

func (rs *relevanceSet) bestRankBytes(host []byte) (uint32, bool) {
	if rs == nil || len(rs.hashes) == 0 {
		return unrankedRank, false
	}
	best, found := unrankedRank, false
	if r, ok := rs.lookupHash(xxh3.Hash(host)); ok {
		best, found = r, true
	}
	for rest := host; ; {
		dot := bytes.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		parent := rest[dot+1:]
		if bytes.IndexByte(parent, '.') < 0 {
			break
		}
		if r, ok := rs.lookupHash(xxh3.Hash(parent)); ok {
			best, found = min(best, r), true
		}
		rest = parent
	}
	return best, found
}

type relevanceMeta struct {
	Version       int               `json:"version"`
	CreatedAt     int64             `json:"created_at"`
	DomainCount   int               `json:"domain_count"`
	SourceHeaders map[string]string `json:"source_headers"`
}

func atomicRename(tmp, dest string) error {
	err := os.Rename(tmp, dest)
	if err != nil && runtime.GOOS == "windows" {
		_ = os.Remove(dest)
		return os.Rename(tmp, dest)
	}
	return err
}

func extractHeaderFingerprint(h http.Header) string {
	etag, lm := strings.TrimSpace(h.Get("ETag")), strings.TrimSpace(h.Get("Last-Modified"))
	if etag != "" || lm != "" {
		return fmt.Sprintf("etag=%s|lm=%s", etag, lm)
	}
	if cl := strings.TrimSpace(h.Get("Content-Length")); cl != "" {
		return "cl=" + cl
	}
	return ""
}

func probeTopListHeaders(client *http.Client) map[string]string {
	out := make(map[string]string, len(defaultTopLists))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, spec := range defaultTopLists {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", uaStr)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if fp := extractHeaderFingerprint(resp.Header); fp != "" {
					mu.Lock()
					out[url] = fp
					mu.Unlock()
				}
			}
		}(spec.URL)
	}
	wg.Wait()
	return out
}

func saveRelevanceCache(cacheDir string, rs *relevanceSet, meta *relevanceMeta) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	binPath, binTmp := filepath.Join(cacheDir, "relevance.bin"), filepath.Join(cacheDir, "relevance.bin.tmp")
	metaPath, metaTmp := filepath.Join(cacheDir, "relevance.meta.json"), filepath.Join(cacheDir, "relevance.meta.json.tmp")

	f, err := os.Create(binTmp)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 256*1024)
	hasher := xxh3.New()

	var hdr [16]byte
	copy(hdr[:8], cacheMagicV3)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(len(rs.hashes)))
	if _, err := bw.Write(hdr[:]); err != nil {
		f.Close()
		return err
	}

	buf := make([]byte, 8192*8)
	for i := 0; i < len(rs.hashes); i += 8192 {
		end := min(i+8192, len(rs.hashes))
		for j, h := range rs.hashes[i:end] {
			binary.LittleEndian.PutUint64(buf[j*8:], h)
		}
		chunk := buf[:(end-i)*8]
		_, _ = hasher.Write(chunk)
		if _, err := bw.Write(chunk); err != nil {
			f.Close()
			return err
		}
	}
	for i := 0; i < len(rs.ranks); i += 8192 {
		end := min(i+8192, len(rs.ranks))
		for j, r := range rs.ranks[i:end] {
			binary.LittleEndian.PutUint32(buf[j*4:], r)
		}
		chunk := buf[:(end-i)*4]
		_, _ = hasher.Write(chunk)
		if _, err := bw.Write(chunk); err != nil {
			f.Close()
			return err
		}
	}

	var trailer [8]byte
	binary.LittleEndian.PutUint64(trailer[:], hasher.Sum64())
	if _, err := bw.Write(trailer[:]); err != nil {
		f.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(metaTmp, metaBytes, 0o644); err != nil {
		return err
	}
	if err := atomicRename(binTmp, binPath); err != nil {
		return err
	}
	return atomicRename(metaTmp, metaPath)
}

func loadRelevanceCache(cacheDir string) (*relevanceSet, error) {
	f, err := os.Open(filepath.Join(cacheDir, "relevance.bin"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 256*1024)

	var hdr [16]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	if string(hdr[:8]) != cacheMagicV3 {
		return nil, fmt.Errorf("cache format %q != %s; rebuilding", string(hdr[:8]), cacheMagicV3)
	}
	count := binary.LittleEndian.Uint64(hdr[8:16])
	if count < minRelevanceDomains {
		return nil, fmt.Errorf("relevance cache count (%d) below minimum", count)
	}
	if expected := int64(count)*12 + 24; stat.Size() != expected {
		return nil, fmt.Errorf("relevance cache truncated (expected %d, got %d)", expected, stat.Size())
	}

	hashes, ranks := make([]uint64, count), make([]uint32, count)
	hasher := xxh3.New()
	buf := make([]byte, 8192*8)

	var prev uint64
	for i := 0; i < int(count); i += 8192 {
		take := min(8192, int(count)-i)
		chunk := buf[:take*8]
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, err
		}
		_, _ = hasher.Write(chunk)
		for j := 0; j < take; j++ {
			v := binary.LittleEndian.Uint64(chunk[j*8:])
			if i+j > 0 && v < prev {
				return nil, errors.New("relevance cache hashes not sorted")
			}
			prev, hashes[i+j] = v, v
		}
	}
	for i := 0; i < int(count); i += 8192 {
		take := min(8192, int(count)-i)
		chunk := buf[:take*4]
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, err
		}
		_, _ = hasher.Write(chunk)
		for j := 0; j < take; j++ {
			ranks[i+j] = binary.LittleEndian.Uint32(chunk[j*4:])
		}
	}

	var trailer [8]byte
	if _, err := io.ReadFull(br, trailer[:]); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint64(trailer[:]) != hasher.Sum64() {
		return nil, errors.New("relevance cache checksum mismatch")
	}
	rs := &relevanceSet{hashes: hashes, ranks: ranks}
	rs.buildIndex()
	return rs, nil
}

// ---------- Streaming Feed Fetching & Parsing ----------

func looksLikeHTMLOrXML(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return true
	}
	sample := bytes.TrimPrefix(body[:min(len(body), 512)], []byte{0xEF, 0xBB, 0xBF})
	t := strings.ToLower(strings.TrimSpace(string(sample)))
	for _, p := range []string{"<!doctype", "<html", "<head", "<body", "<?xml"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func forEachLine(r io.Reader, fn func(line []byte)) error {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64*1024)
	}
	var overflow []byte
	for {
		frag, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			overflow = append(overflow, frag...)
			continue
		}
		if len(overflow) > 0 {
			fn(append(overflow, frag...))
			overflow = overflow[:0]
		} else if len(frag) > 0 {
			fn(frag)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func streamWithRetry(client *http.Client, url string, checkBodyHTML bool, consume func(r io.Reader, fp string) error) error {
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", uaStr)
		resp, err := client.Do(req)
		if err == nil {
			ct := resp.Header.Get("Content-Type")
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			} else if strings.Contains(strings.ToLower(ct), "html") {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				err = fmt.Errorf("HTML response rejected (%s)", ct)
			} else {
				br := bufio.NewReaderSize(resp.Body, 64*1024)
				if checkBodyHTML {
					sample, pErr := br.Peek(512)
					if pErr != nil && !errors.Is(pErr, io.EOF) && !errors.Is(pErr, bufio.ErrBufferFull) {
						err = pErr
					} else if looksLikeHTMLOrXML(ct, sample) {
						err = errors.New("HTML/XML error page in feed body")
					}
				}
				if err == nil {
					err = consume(br, extractHeaderFingerprint(resp.Header))
				}
				resp.Body.Close()
				if err == nil {
					return nil
				}
			}
		}
		if attempt == 4 {
			return err
		}
		if attempt >= 2 {
			logWarn("Fetch attempt %d/5 failed for %s: %v. Retrying...", attempt+1, url, err)
		}
		time.Sleep(time.Duration(1500*(1<<attempt))*time.Millisecond + jitterMs(500))
	}
	return errors.New("unreachable")
}

func nthCSVColBytes(line []byte, col int) ([]byte, bool) {
	cur, start := 0, 0
	for i, b := range line {
		if b == ',' {
			if cur == col {
				return line[start:i], true
			}
			cur++
			start = i + 1
		}
	}
	if cur == col {
		return line[start:], true
	}
	return nil, false
}

func parseCSVStream(r io.Reader, col int, skipHeader bool) ([]rankedHash, error) {
	items := make([]rankedHash, 0, 256_000)
	scratch := make([]byte, 0, 256)
	rowIdx, rank := 0, uint32(0)

	err := forEachLine(r, func(line []byte) {
		cur := rowIdx
		rowIdx++
		if skipHeader && cur == 0 {
			return
		}
		rank++
		rawCol, ok := nthCSVColBytes(line, col)
		if !ok {
			return
		}
		trimmed := bytes.Trim(bytes.TrimSpace(rawCol), `"`)
		if clean, ok := normalizeDomainBytes(trimmed, &scratch); ok {
			items = append(items, rankedHash{hash: xxh3.Hash(stripWWWBytes(clean)), rank: rank})
		}
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(items, func(a, b rankedHash) int {
		if c := cmp.Compare(a.hash, b.hash); c != 0 {
			return c
		}
		return cmp.Compare(a.rank, b.rank)
	})
	return slices.CompactFunc(items, func(a, b rankedHash) bool { return a.hash == b.hash }), nil
}

func buildFreshRelevanceDataset(client *http.Client) (*relevanceSet, map[string]string, error) {
	logInfo("Fetching fresh ranked relevance datasets directly from sources...")
	type itemResult struct {
		url, fp string
		items   []rankedHash
	}
	results := make([]itemResult, len(defaultTopLists))
	var wg sync.WaitGroup

	for i, spec := range defaultTopLists {
		wg.Add(1)
		go func(i int, url, comp string, col int, skip bool) {
			defer wg.Done()
			var parsed []rankedHash
			var fp string
			err := streamWithRetry(client, url, comp == "raw", func(r io.Reader, headerFP string) error {
				fp = headerFP
				switch comp {
				case "zip":
					raw, err := io.ReadAll(r)
					if err != nil {
						return err
					}
					zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
					if err != nil {
						return err
					}
					var target *zip.File
					for _, f := range zr.File {
						l := strings.ToLower(f.Name)
						if (strings.HasSuffix(l, ".csv") || strings.HasSuffix(l, ".txt")) && !strings.HasSuffix(l, "/") {
							target = f
							break
						}
					}
					if target == nil && len(zr.File) > 0 {
						target = zr.File[0]
					}
					if target == nil {
						return nil
					}
					rc, err := target.Open()
					if err != nil {
						return err
					}
					defer rc.Close()
					parsed, err = parseCSVStream(rc, col, skip)
					return err
				case "gzip":
					gz, err := gzip.NewReader(r)
					if err != nil {
						return err
					}
					defer gz.Close()
					parsed, err = parseCSVStream(gz, col, skip)
					return err
				default:
					var err error
					parsed, err = parseCSVStream(r, col, skip)
					return err
				}
			})
			if err != nil {
				logWarn("Failed top list (%s): %v", url, err)
			} else {
				logInfo("Fetched & parsed %d ranked domains from %s", len(parsed), url)
			}
			results[i] = itemResult{url: url, fp: fp, items: parsed}
		}(i, spec.URL, spec.Compression, spec.Col, spec.SkipHeader)
	}
	wg.Wait()

	headersMap := make(map[string]string, len(results))
	active := make([][]rankedHash, 0, len(results))
	maxLen := 0
	for i := range results {
		if results[i].fp != "" {
			headersMap[results[i].url] = results[i].fp
		}
		if len(results[i].items) > 0 {
			active = append(active, results[i].items)
			maxLen = max(maxLen, len(results[i].items))
			results[i].items = nil
		}
	}

	estCap := maxLen + maxLen/4
	hashes, ranks := make([]uint64, 0, estCap), make([]uint32, 0, estCap)
	cursors := make([]int, len(active))

	for len(active) > 0 {
		minHash := active[0][cursors[0]].hash
		for i := 1; i < len(active); i++ {
			minHash = min(minHash, active[i][cursors[i]].hash)
		}
		bestRank := unrankedRank
		for i := 0; i < len(active); {
			if it := active[i][cursors[i]]; it.hash == minHash {
				bestRank = min(bestRank, it.rank)
				cursors[i]++
				if cursors[i] == len(active[i]) {
					last := len(active) - 1
					active[i], cursors[i] = active[last], cursors[last]
					active[last] = nil
					active, cursors = active[:last], cursors[:last]
					continue
				}
			}
			i++
		}
		hashes = append(hashes, minHash)
		ranks = append(ranks, bestRank)
	}

	if len(hashes) < minRelevanceDomains {
		return nil, nil, fmt.Errorf("relevance dataset critically low (%d domains)", len(hashes))
	}
	rs := &relevanceSet{hashes: hashes, ranks: ranks}
	rs.buildIndex()
	logInfo("Ranked relevance dataset compiled: %d hashed root domains.", len(hashes))
	return rs, headersMap, nil
}

func resolveRelevanceDataset(client *http.Client, cfg *appConfig) (*relevanceSet, string, error) {
	_, statErr := os.Stat(filepath.Join(cfg.RelevanceCacheDir, "relevance.bin"))
	binExists := statErr == nil
	var cachedMeta *relevanceMeta
	if binExists {
		if data, err := os.ReadFile(filepath.Join(cfg.RelevanceCacheDir, "relevance.meta.json")); err == nil {
			var m relevanceMeta
			if json.Unmarshal(data, &m) == nil {
				cachedMeta = &m
			}
		}
	}
	now := time.Now().Unix()

	if !cfg.ForceRefreshRelevance && cachedMeta != nil && cachedMeta.Version >= 3 {
		ageSecs := max(now-cachedMeta.CreatedAt, 0)
		useCache := false
		if ageSecs < cfg.RelevanceMinRefreshSecs {
			logInfo("Relevance cache is %.1fh old (under %dh min refresh); loading from disk.",
				float64(ageSecs)/3600.0, cfg.RelevanceMinRefreshSecs/3600)
			useCache = true
		} else if ageSecs < cfg.RelevanceTTLSecs {
			logInfo("Relevance cache is %.1fd old; probing upstream HEAD headers...", float64(ageSecs)/86400.0)
			changed := ""
			for u, newFP := range probeTopListHeaders(client) {
				if oldFP, ok := cachedMeta.SourceHeaders[u]; ok && newFP != oldFP {
					changed = u
					break
				}
			}
			if changed != "" {
				logInfo("Upstream top-list changed (%s); refreshing relevance cache.", changed)
			} else {
				logInfo("No upstream top-list changes; reusing cached relevance dataset.")
				useCache = true
			}
		}
		if useCache {
			if rs, err := loadRelevanceCache(cfg.RelevanceCacheDir); err == nil {
				logInfo("Loaded %d ranked root domains from relevance cache.", rs.len())
				return rs, "cache-hit", nil
			} else {
				logWarn("Cached relevance.bin unusable (%v); rebuilding.", err)
			}
		}
	}

	rs, headers, err := buildFreshRelevanceDataset(client)
	if err == nil {
		meta := &relevanceMeta{Version: 3, CreatedAt: now, DomainCount: rs.len(), SourceHeaders: headers}
		if saveErr := saveRelevanceCache(cfg.RelevanceCacheDir, rs, meta); saveErr != nil {
			logWarn("Failed saving relevance cache: %v", saveErr)
		} else {
			logInfo("Saved ranked relevance cache to %s (%d entries).", cfg.RelevanceCacheDir, rs.len())
		}
		return rs, "refreshed", nil
	}

	if binExists {
		logWarn("Fresh relevance fetch failed (%v); falling back to stale cache...", err)
		if stale, loadErr := loadRelevanceCache(cfg.RelevanceCacheDir); loadErr == nil {
			logWarn("Self-healed using stale relevance cache (%d entries).", stale.len())
			return stale, "stale-fallback", nil
		}
	}
	return nil, "", fmt.Errorf("relevance dataset unavailable: %w", err)
}

type sourceSpec struct {
	Name            string
	URLs            []string
	EnableRelevance bool
}

func parseSources(table map[string]any, isIP bool) []sourceSpec {
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	slices.Sort(names)

	out := make([]sourceSpec, 0, len(names))
	for _, name := range names {
		spec := sourceSpec{Name: name, EnableRelevance: !isIP}
		switch val := table[name].(type) {
		case string:
			spec.URLs = []string{val}
		case []any:
			for _, u := range val {
				if s, ok := u.(string); ok {
					spec.URLs = append(spec.URLs, s)
				}
			}
		case map[string]any:
			if arr, ok := val["urls"].([]any); ok {
				for _, u := range arr {
					if s, ok := u.(string); ok {
						spec.URLs = append(spec.URLs, s)
					}
				}
			} else if u, ok := val["url"].(string); ok {
				spec.URLs = []string{u}
			}
			if !isIP {
				if rel, ok := val["relevance"].(bool); ok {
					spec.EnableRelevance = rel
				}
			}
		}
		out = append(out, spec)
	}
	return out
}

func ingestDomainTokenBytes(rawTok []byte, rel *relevanceSet, enforceRelevance bool, kept map[string]uint32, scratch *[]byte) {
	if idx := bytes.IndexByte(rawTok, '$'); idx >= 0 {
		for mods := rawTok[idx+1:]; len(mods) > 0; {
			opt := mods
			if c := bytes.IndexByte(mods, ','); c >= 0 {
				opt, mods = mods[:c], mods[c+1:]
			} else {
				mods = nil
			}
			if bytes.EqualFold(opt, []byte("badfilter")) {
				return
			}
		}
		rawTok = rawTok[:idx]
	}
	token := bytes.TrimPrefix(rawTok, []byte("||"))
	if idx := bytes.IndexByte(token, '^'); idx >= 0 {
		token = token[:idx]
	}
	clean, ok := normalizeDomainBytes(token, scratch)
	if !ok {
		return
	}
	if _, exists := kept[string(clean)]; exists {
		return
	}
	rank := unrankedRank
	if rel != nil {
		best, found := rel.bestRankBytes(stripWWWBytes(clean))
		if enforceRelevance && !found {
			return
		}
		if found {
			rank = best
		}
	}
	kept[string(clean)] = rank
}

func fetchFeedSource(client *http.Client, spec sourceSpec, rel *relevanceSet) (map[string]uint32, error) {
	kept := make(map[string]uint32, 16_384)
	scratch := make([]byte, 0, 256)

	for _, u := range spec.URLs {
		err := streamWithRetry(client, u, true, func(r io.Reader, _ string) error {
			return forEachLine(r, func(rawLine []byte) {
				line := bytes.TrimSpace(rawLine)
				if len(line) == 0 || line[0] == '#' || line[0] == '!' || line[0] == '/' ||
					bytes.HasPrefix(line, []byte("@@")) || bytes.Contains(line, []byte("##")) ||
					bytes.Contains(line, []byte("#@#")) || bytes.Contains(line, []byte("#?#")) ||
					bytes.Contains(line, []byte("#$#")) {
					return
				}
				if idx := bytes.IndexAny(line, "#!;"); idx >= 0 {
					line = bytes.TrimSpace(line[:idx])
				}
				if len(line) == 0 {
					return
				}
				if bytes.IndexAny(line, " \t") < 0 {
					ingestDomainTokenBytes(line, rel, spec.EnableRelevance, kept, &scratch)
					return
				}
				fields := bytes.Fields(line)
				var addr netip.Addr
				if addr.UnmarshalText(fields[0]) == nil {
					for _, tok := range fields[1:] {
						ingestDomainTokenBytes(tok, rel, spec.EnableRelevance, kept, &scratch)
					}
				} else {
					ingestDomainTokenBytes(fields[len(fields)-1], rel, spec.EnableRelevance, kept, &scratch)
				}
			})
		})
		if err != nil {
			return nil, err
		}
	}
	logInfo("Fetched %s: %d kept (relevance=%t)", spec.Name, len(kept), spec.EnableRelevance)
	return kept, nil
}

func parseIPTokenBytes(rawTok []byte) (netip.Prefix, bool) {
	tok := bytes.Trim(rawTok, "[]")
	if bytes.IndexAny(tok, ".:") < 0 {
		return netip.Prefix{}, false
	}
	if bytes.IndexByte(tok, '.') >= 0 && bytes.Count(tok, []byte(":")) == 1 {
		tok, _, _ = bytes.Cut(tok, []byte(":"))
	} else if v6, _, found := bytes.Cut(rawTok, []byte("]:")); found {
		tok = bytes.TrimPrefix(v6, []byte("["))
	}

	var p netip.Prefix
	if bytes.IndexByte(tok, '/') >= 0 {
		if p.UnmarshalText(tok) != nil {
			return netip.Prefix{}, false
		}
		p = p.Masked()
	} else {
		var addr netip.Addr
		if addr.UnmarshalText(tok) != nil {
			return netip.Prefix{}, false
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p, true
}

func fetchIPSource(client *http.Client, spec sourceSpec) (map[netip.Prefix]struct{}, error) {
	networks := make(map[netip.Prefix]struct{}, 4096)
	isSep := func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '"' || r == '\'' }

	for _, u := range spec.URLs {
		err := streamWithRetry(client, u, true, func(r io.Reader, _ string) error {
			return forEachLine(r, func(rawLine []byte) {
				line := bytes.TrimSpace(rawLine)
				if len(line) == 0 || line[0] == '#' || line[0] == ';' || line[0] == '/' {
					return
				}
				if idx := bytes.IndexAny(line, "#;"); idx >= 0 {
					line = line[:idx]
				}
				if idx := bytes.Index(line, []byte("//")); idx >= 0 {
					line = line[:idx]
				}
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					return
				}
				if bytes.IndexAny(line, " \t,\"'") < 0 {
					if p, ok := parseIPTokenBytes(line); ok {
						networks[p] = struct{}{}
					}
					return
				}
				for _, tok := range bytes.FieldsFunc(line, isSep) {
					if p, ok := parseIPTokenBytes(tok); ok {
						networks[p] = struct{}{}
					}
				}
			})
		})
		if err != nil {
			return nil, err
		}
	}
	logInfo("Fetched IP feed %s: %d unique subnets/IPs", spec.Name, len(networks))
	return networks, nil
}

func fetchSpamTLDs(client *http.Client, url string) (string, map[string]struct{}, error) {
	tldSet := make(map[string]struct{})
	err := streamWithRetry(client, url, true, func(r io.Reader, _ string) error {
		return forEachLine(r, func(rawLine []byte) {
			l := strings.ToLower(string(bytes.TrimSpace(rawLine)))
			if l != "" && l[0] != '#' && l[0] != '!' && l[0] != '/' {
				if fields := strings.Fields(l); len(fields) > 0 {
					clean := strings.Trim(strings.TrimPrefix(fields[len(fields)-1], "*."), ".")
					if clean != "" && !strings.ContainsAny(clean, ".*") {
						tldSet[clean] = struct{}{}
					}
				}
			}
		})
	})
	if err != nil {
		return "", nil, err
	}
	if len(tldSet) == 0 {
		return "", nil, fmt.Errorf("zero TLDs parsed from %s", url)
	}
	sorted := make([]string, 0, len(tldSet))
	for t := range tldSet {
		sorted = append(sorted, t)
	}
	slices.Sort(sorted)
	return fmt.Sprintf(`any(dns.domains[*] matches "(?i)\.(%s)$")`, strings.Join(sorted, "|")), tldSet, nil
}

// ---------- Policy Compilation, Dedup, Rank Trimming & Hash Bucketing ----------

type fetchedFeed struct {
	IsIP    bool
	Domains map[string]uint32
	IPs     map[netip.Prefix]struct{}
}

type rankedEntry struct {
	Value string
	Rank  uint32
}

type compiledPolicy struct {
	Policy                                        policyConfig
	Priority                                      int
	Trimmable                                     bool
	Entries                                       []rankedEntry
	Chunks                                        [][]string
	RawCount, DedupedCount, TrimmedCount, Guarded int
}

func buildPolicySets(
	cfg *appConfig,
	policies []policyConfig,
	fetched map[string]fetchedFeed,
	spamTLDs map[string]struct{},
	hasActiveSpamTLD bool,
) ([]compiledPolicy, []string) {
	type rawPolicySet struct {
		policy       policyConfig
		priority     int
		trimmable    bool
		domains      map[string]uint32
		ips          []string
		rawCount     int
		guardedCount int
		guardedHits  []string
	}

	rawSets := make([]rawPolicySet, len(policies))
	sem := make(chan struct{}, cfg.MaxWorkers)
	var wg sync.WaitGroup

	for i, pol := range policies {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p policyConfig) {
			defer wg.Done()
			defer func() { <-sem }()

			prio := p.resolvedPriority(cfg)
			if p.resolvedType() == "IP" {
				var b netipx.IPSetBuilder
				for _, inc := range p.Include {
					if f, ok := fetched[inc]; ok && f.IsIP {
						for pf := range f.IPs {
							b.AddPrefix(pf)
						}
					}
				}
				for _, exc := range p.Exclude {
					if f, ok := fetched[exc]; ok && f.IsIP {
						for pf := range f.IPs {
							b.RemovePrefix(pf)
						}
					}
				}
				var collapsed []string
				if ipSet, err := b.IPSet(); err == nil && ipSet != nil {
					pfs := ipSet.Prefixes()
					collapsed = make([]string, len(pfs))
					for j, pf := range pfs {
						collapsed[j] = pf.String()
					}
				}
				rawSets[i] = rawPolicySet{policy: p.clone(), priority: prio, ips: collapsed, rawCount: len(collapsed)}
				return
			}

			estCap := 0
			for _, inc := range p.Include {
				if f, ok := fetched[inc]; ok && !f.IsIP {
					estCap = max(estCap, len(f.Domains))
				}
			}
			pSet := make(map[string]uint32, estCap)
			for _, inc := range p.Include {
				if f, ok := fetched[inc]; ok && !f.IsIP {
					for d, r := range f.Domains {
						if prev, exists := pSet[d]; !exists || r < prev {
							pSet[d] = r
						}
					}
				}
			}
			for _, exc := range p.Exclude {
				if f, ok := fetched[exc]; ok && !f.IsIP {
					for d := range f.Domains {
						delete(pSet, d)
					}
				}
			}

			var guardedHits []string
			if p.resolvedAction() != "allow" {
				if len(spamTLDs) > 0 && (p.UseSpamTLD || hasActiveSpamTLD) {
					for d := range pSet {
						if dot := strings.LastIndexByte(d, '.'); dot >= 0 {
							if _, blocked := spamTLDs[d[dot+1:]]; blocked {
								delete(pSet, d)
							}
						}
					}
				}
				if len(cfg.NeverBlock) > 0 {
					for d := range pSet {
						if cfg.isNeverBlocked(d) {
							delete(pSet, d)
							guardedHits = append(guardedHits, fmt.Sprintf("%s (%s)", d, p.Name))
						}
					}
				}
			}

			for d, r := range pSet {
				hasParent := false
				for rest := d; ; {
					dot := strings.IndexByte(rest, '.')
					if dot < 0 {
						break
					}
					parent := rest[dot+1:]
					if strings.IndexByte(parent, '.') < 0 {
						break
					}
					if pr, ok := pSet[parent]; ok {
						if r < pr {
							pSet[parent] = r
						}
						hasParent = true
					}
					rest = parent
				}
				if hasParent {
					delete(pSet, d)
				}
			}

			rawSets[i] = rawPolicySet{
				policy: p.clone(), priority: prio, trimmable: p.isTrimmable(),
				domains: pSet, rawCount: len(pSet), guardedCount: len(guardedHits), guardedHits: guardedHits,
			}
		}(i, pol)
	}
	wg.Wait()

	var guardWarnings []string
	totalRaw := 0
	for _, rs := range rawSets {
		guardWarnings = append(guardWarnings, rs.guardedHits...)
		totalRaw += len(rs.domains)
	}
	if len(guardWarnings) > 0 {
		slices.Sort(guardWarnings)
		logWarn("Config never_block stripped %d domain(s): %s", len(guardWarnings), strings.Join(guardWarnings, ", "))
	}

	order := make([]int, len(rawSets))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		if c := cmp.Compare(rawSets[a].priority, rawSets[b].priority); c != 0 {
			return c
		}
		return cmp.Compare(rawSets[a].policy.Name, rawSets[b].policy.Name)
	})

	dedupCap := min(totalRaw, maxSafeDomains)
	globalStable := make(map[string]struct{}, dedupCap/2)
	globalAll := make(map[string]struct{}, dedupCap)
	scopedStable := make(map[string]map[string]struct{})
	scopedAll := make(map[string]map[string]struct{})
	dedupCounts := make([]int, len(rawSets))

	for _, scopedPass := range []bool{false, true} {
		for _, idx := range order {
			rs := &rawSets[idx]
			if rs.policy.resolvedType() != "DOMAIN" || rs.policy.resolvedAction() == "allow" || rs.policy.isScoped(cfg) != scopedPass {
				continue
			}
			gLookup := globalStable
			if rs.trimmable {
				gLookup = globalAll
			}
			var pLookup, pStable, pAll map[string]struct{}
			if scopedPass {
				idKey := rs.policy.effectiveIdentity(cfg)
				if pStable = scopedStable[idKey]; pStable == nil {
					pStable = make(map[string]struct{}, len(rs.domains))
					scopedStable[idKey] = pStable
				}
				if pAll = scopedAll[idKey]; pAll == nil {
					pAll = make(map[string]struct{}, len(rs.domains))
					scopedAll[idKey] = pAll
				}
				pLookup = pStable
				if rs.trimmable {
					pLookup = pAll
				}
			}

			removed := 0
			for d := range rs.domains {
				if hasSuffixDomain(d, gLookup) || (pLookup != nil && hasSuffixDomain(d, pLookup)) {
					delete(rs.domains, d)
					removed++
				}
			}
			dedupCounts[idx] = removed
			for d := range rs.domains {
				if scopedPass {
					pAll[d] = struct{}{}
					if !rs.trimmable {
						pStable[d] = struct{}{}
					}
				} else {
					globalAll[d] = struct{}{}
					if !rs.trimmable {
						globalStable[d] = struct{}{}
					}
				}
			}
			if removed > 0 {
				logInfo("Cross-policy dedup removed %d duplicate domain(s) from '%s' (priority %d)",
					removed, rs.policy.Name, rs.priority)
			}
		}
	}

	out := make([]compiledPolicy, len(order))
	for outIdx, idx := range order {
		rs := rawSets[idx]
		if rs.policy.resolvedType() == "IP" {
			entries := make([]rankedEntry, len(rs.ips))
			for j, cidr := range rs.ips {
				entries[j] = rankedEntry{Value: cidr}
			}
			out[outIdx] = compiledPolicy{Policy: rs.policy, Priority: rs.priority, Entries: entries, RawCount: rs.rawCount}
			continue
		}
		entries := make([]rankedEntry, 0, len(rs.domains))
		for d, r := range rs.domains {
			entries = append(entries, rankedEntry{Value: d, Rank: r})
		}
		slices.SortFunc(entries, func(a, b rankedEntry) int {
			if c := cmp.Compare(a.Rank, b.Rank); c != 0 {
				return c
			}
			return cmp.Compare(a.Value, b.Value)
		})
		out[outIdx] = compiledPolicy{
			Policy: rs.policy, Priority: rs.priority, Trimmable: rs.trimmable,
			Entries: entries, RawCount: rs.rawCount, DedupedCount: dedupCounts[idx], Guarded: rs.guardedCount,
		}
	}
	return out, guardWarnings
}

func sumMinCapacity(compiled []compiledPolicy, maxListSize int) (entries, minLists int) {
	for _, cp := range compiled {
		entries += len(cp.Entries)
		minLists += divCeil(len(cp.Entries), maxListSize)
	}
	return
}

func trimByRank(compiled []compiledPolicy, activeQuota, maxActiveLists, maxListSize int) []string {
	totalEntries, minLists := sumMinCapacity(compiled, maxListSize)
	if totalEntries <= activeQuota && minLists <= maxActiveLists {
		return nil
	}

	revOrder := make([]int, 0, len(compiled))
	for i := range compiled {
		if compiled[i].Trimmable && len(compiled[i].Entries) > 0 {
			revOrder = append(revOrder, i)
		}
	}
	slices.SortFunc(revOrder, func(a, b int) int {
		if c := cmp.Compare(compiled[b].Priority, compiled[a].Priority); c != 0 {
			return c
		}
		return cmp.Compare(compiled[b].Policy.Name, compiled[a].Policy.Name)
	})

	for pass := 0; pass < 2 && totalEntries > activeQuota; pass++ {
		for _, idx := range revOrder {
			if totalEntries <= activeQuota {
				break
			}
			cp := &compiled[idx]
			floor := 0
			if pass == 0 {
				floor = min(len(cp.Entries), coreRankProtectionCap)
			}
			if avail := len(cp.Entries) - floor; avail > 0 {
				drop := min(avail, totalEntries-activeQuota)
				cp.Entries = cp.Entries[:len(cp.Entries)-drop]
				cp.TrimmedCount += drop
				totalEntries -= drop
			}
		}
	}

	_, minLists = sumMinCapacity(compiled, maxListSize)
	for minLists > maxActiveLists {
		bestIdx, bestDrop, bestPrio := -1, math.MaxInt, -1
		for _, idx := range revOrder {
			n := len(compiled[idx].Entries)
			if n == 0 {
				continue
			}
			tail := n % maxListSize
			if tail == 0 {
				tail = maxListSize
			}
			if tail < bestDrop || (tail == bestDrop && compiled[idx].Priority > bestPrio) {
				bestIdx, bestDrop, bestPrio = idx, tail, compiled[idx].Priority
			}
		}
		if bestIdx < 0 {
			break
		}
		cp := &compiled[bestIdx]
		cp.Entries = cp.Entries[:len(cp.Entries)-bestDrop]
		cp.TrimmedCount += bestDrop
		minLists--
	}

	var warnings []string
	for _, cp := range compiled {
		if cp.TrimmedCount > 0 {
			worst := "none"
			if n := len(cp.Entries); n > 0 {
				if r := cp.Entries[n-1].Rank; r == unrankedRank {
					worst = "unranked"
				} else {
					worst = fmt.Sprintf("#%d", r)
				}
			}
			msg := fmt.Sprintf("Rank-trimmed %d low-popularity domains from '%s' (kept %d, worst kept rank: %s)",
				cp.TrimmedCount, cp.Policy.Name, len(cp.Entries), worst)
			logWarn("%s", msg)
			warnings = append(warnings, msg)
		}
	}
	return warnings
}

func bucketEntries(entries []rankedEntry, numBuckets, maxListSize int) [][]string {
	if len(entries) == 0 || numBuckets <= 0 {
		return nil
	}
	if numBuckets == 1 {
		out := make([]string, len(entries))
		for i, e := range entries {
			out[i] = e.Value
		}
		slices.Sort(out)
		return [][]string{out}
	}

	buckets := make([][]string, numBuckets)
	avg := min(len(entries)/numBuckets+16, maxListSize)
	for i := range buckets {
		buckets[i] = make([]string, 0, avg)
	}
	for _, e := range entries {
		idx := int(xxh3.HashString(e.Value) % uint64(numBuckets))
		buckets[idx] = append(buckets[idx], e.Value)
	}

	var overflow []string
	for i := range buckets {
		slices.Sort(buckets[i])
		if len(buckets[i]) > maxListSize {
			overflow = append(overflow, buckets[i][maxListSize:]...)
			buckets[i] = buckets[i][:maxListSize]
		}
	}
	if len(overflow) > 0 {
		slices.Sort(overflow)
		touched := make([]bool, numBuckets)
		for _, item := range overflow {
			start := int(xxh3.HashString(item) % uint64(numBuckets))
			for step := 1; step <= numBuckets; step++ {
				if b := (start + step) % numBuckets; len(buckets[b]) < maxListSize {
					buckets[b] = append(buckets[b], item)
					touched[b] = true
					break
				}
			}
		}
		for i, wasTouched := range touched {
			if wasTouched {
				slices.Sort(buckets[i])
			}
		}
	}

	nonEmpty := buckets[:0]
	for _, b := range buckets {
		if len(b) > 0 {
			nonEmpty = append(nonEmpty, b)
		}
	}
	return nonEmpty
}

func assignHashBuckets(compiled []compiledPolicy, existingLists []gatewayList, maxListSize, maxActiveLists int) int {
	existingCounts := make(map[string]int, len(compiled))
	for _, cp := range compiled {
		if cp.Policy.Prefix == "" {
			continue
		}
		for _, l := range existingLists {
			if _, ok := parseChunkIndex(l.Name, cp.Policy.Prefix); ok {
				existingCounts[cp.Policy.Prefix]++
			}
		}
	}

	targetSize, minFillSize := max((maxListSize*90)/100, 1), max((maxListSize*75)/100, 1)
	bucketCounts, minBuckets := make([]int, len(compiled)), make([]int, len(compiled))
	totalBuckets := 0

	for i, cp := range compiled {
		n := len(cp.Entries)
		if n == 0 {
			continue
		}
		if n <= maxListSize {
			bucketCounts[i], minBuckets[i] = 1, 1
			totalBuckets++
			continue
		}
		minB, targetB, maxStickyB := divCeil(n, maxListSize), divCeil(n, targetSize), divCeil(n, minFillSize)
		minBuckets[i] = minB
		if existingB := existingCounts[cp.Policy.Prefix]; existingB >= minB && existingB <= maxStickyB {
			bucketCounts[i] = existingB
		} else {
			bucketCounts[i] = targetB
		}
		totalBuckets += bucketCounts[i]
	}

	for totalBuckets > maxActiveLists {
		slackestIdx, lowestFill := -1, math.MaxFloat64
		for i, cp := range compiled {
			if bucketCounts[i] > minBuckets[i] {
				if fill := float64(len(cp.Entries)) / float64(bucketCounts[i]); fill < lowestFill {
					lowestFill, slackestIdx = fill, i
				}
			}
		}
		if slackestIdx < 0 {
			break
		}
		totalBuckets -= bucketCounts[slackestIdx] - minBuckets[slackestIdx]
		bucketCounts[slackestIdx] = minBuckets[slackestIdx]
	}

	actualTotal := 0
	for i := range compiled {
		compiled[i].Chunks = bucketEntries(compiled[i].Entries, bucketCounts[i], maxListSize)
		actualTotal += len(compiled[i].Chunks)
	}
	return actualTotal
}

func compileCategoryExpression(p policyConfig) string {
	var parts []string
	for _, spec := range []struct {
		vals  []any
		field string
	}{
		{p.SecurityCategories, "dns.security_category[*]"},
		{p.ContentCategories, "dns.content_category[*]"},
		{p.AppIDs, "app.ids[*]"},
	} {
		if len(spec.vals) > 0 {
			ids := make([]string, len(spec.vals))
			for i, v := range spec.vals {
				ids[i] = strings.Trim(fmt.Sprint(v), `"`)
			}
			parts = append(parts, fmt.Sprintf("any(%s in {%s})", spec.field, strings.Join(ids, " ")))
		}
	}
	if len(p.Domains) > 0 {
		quoted := make([]string, len(p.Domains))
		for i, d := range p.Domains {
			quoted[i] = fmt.Sprintf(`"%s"`, d)
		}
		parts = append(parts, fmt.Sprintf("any(dns.domains[*] in {%s})", strings.Join(quoted, " ")))
	}
	return strings.Join(parts, " or ")
}

// ---------- Rule, Chunk & Cleanup Helpers ----------

func parseChunkIndex(listName, prefix string) (int, bool) {
	if prefix == "" {
		return 0, false
	}
	suffix, ok := strings.CutPrefix(listName, prefix+" ")
	if !ok || suffix == "" {
		return 0, false
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(suffix)
	return n, err == nil
}

func hashChunk(chunk []string) string {
	h := sha256.New()
	comma := []byte(",")
	for i, item := range chunk {
		if i > 0 {
			_, _ = h.Write(comma)
		}
		_, _ = io.WriteString(h, item)
	}
	var sum [sha256.Size]byte
	return hex.EncodeToString(h.Sum(sum[:0]))
}

func chunkMatchesRemote(target gatewayList, expectedName, rawHash string, rawLen int) bool {
	if target.Name != expectedName {
		return false
	}
	if storedHash, storedLen, hasSep := strings.Cut(target.Description, ":"); hasSep && storedHash == rawHash {
		if n, err := strconv.ParseInt(storedLen, 10, 64); err == nil {
			return target.Count == nil || *target.Count == n
		}
	}
	return target.Description == rawHash && (target.Count == nil || int(*target.Count) == rawLen)
}

func clauseReferencesID(clause, id string) bool {
	if id == "" {
		return false
	}
	needle := "$" + id
	for start := 0; ; {
		pos := strings.Index(clause[start:], needle)
		if pos < 0 {
			return false
		}
		end := start + pos + len(needle)
		if end >= len(clause) {
			return true
		}
		c := clause[end]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return true
		}
		start = end
	}
}

func stripListsFromTraffic(traffic string, listIDs []string) (string, bool) {
	clauses := strings.Split(traffic, " or ")
	kept := make([]string, 0, len(clauses))
	for _, cl := range clauses {
		if !slices.ContainsFunc(listIDs, func(id string) bool { return clauseReferencesID(cl, id) }) {
			kept = append(kept, cl)
		}
	}
	return strings.Join(kept, " or "), len(kept) > 0
}

func buildRuleUpdatePayload(rule gatewayRule, enabled bool, traffic string) map[string]any {
	filters := rule.Filters
	if len(filters) == 0 {
		filters = []string{"dns"}
	}
	action := rule.Action
	if action == "" {
		action = "block"
	}
	payload := map[string]any{
		"name": rule.Name, "action": action, "enabled": enabled, "filters": filters, "traffic": traffic,
	}
	if rule.Identity != "" {
		payload["identity"] = rule.Identity
	}
	if rule.RuleSettings != nil {
		cp := make(map[string]any, len(rule.RuleSettings))
		for k, v := range rule.RuleSettings {
			cp[k] = v
		}
		payload["rule_settings"] = cp
	}
	for k, raw := range map[string]json.RawMessage{
		"device_posture": rule.DevicePosture, "schedule": rule.Schedule,
		"precedence": rule.Precedence, "description": rule.Description,
	} {
		if isNonNullRaw(raw) {
			payload[k] = raw
		}
	}
	return payload
}

func ensureSpamAllowPrecedence(cf *cloudflareAPI, spamTLDBlockNames map[string]struct{}, existingRules []gatewayRule) []string {
	if len(spamTLDBlockNames) == 0 {
		return nil
	}
	allowIdx := slices.IndexFunc(existingRules, func(r gatewayRule) bool { return r.Name == spamAllowRuleName })
	if allowIdx < 0 {
		return nil
	}
	allowPrec, ok := parseRulePrecedence(existingRules[allowIdx].Precedence)
	if !ok {
		return nil
	}

	var spamBlockIndices []int
	minSpamPrec := int64(math.MaxInt64)
	for i, r := range existingRules {
		if _, isSpam := spamTLDBlockNames[r.Name]; isSpam {
			if p, ok := parseRulePrecedence(r.Precedence); ok {
				spamBlockIndices = append(spamBlockIndices, i)
				minSpamPrec = min(minSpamPrec, p)
			}
		}
	}
	if len(spamBlockIndices) == 0 {
		return nil
	}
	if allowPrec < minSpamPrec {
		logInfo("Rule precedence verified: '%s' (%d) precedes spam-TLD block rule(s) (min %d).",
			spamAllowRuleName, allowPrec, minSpamPrec)
		return nil
	}

	var prevPrec, maxDNSPrec int64
	usedPrecs := make(map[int64]struct{}, len(existingRules))
	for i, r := range existingRules {
		if !r.isDNSRule() {
			continue
		}
		if p, ok := parseRulePrecedence(r.Precedence); ok {
			maxDNSPrec = max(maxDNSPrec, p)
			if i != allowIdx {
				usedPrecs[p] = struct{}{}
				if p < minSpamPrec && p > prevPrec {
					prevPrec = p
				}
			}
		}
	}

	setPrec := func(idx int, newPrec int64) error {
		r := &existingRules[idx]
		payload := buildRuleUpdatePayload(*r, r.Enabled, r.Traffic)
		payload["precedence"] = newPrec
		updated, err := cf.updateRule(r.ID, payload)
		if err != nil {
			return err
		}
		if updated != nil {
			existingRules[idx] = *updated
		} else if raw, err := json.Marshal(newPrec); err == nil {
			existingRules[idx].Precedence = raw
		}
		return nil
	}

	if prevPrec+1 < minSpamPrec {
		target := prevPrec + (minSpamPrec-prevPrec)/2
		if _, taken := usedPrecs[target]; taken {
			for cand := minSpamPrec - 1; cand > prevPrec; cand-- {
				if _, used := usedPrecs[cand]; !used {
					target = cand
					break
				}
			}
		}
		if err := setPrec(allowIdx, target); err != nil {
			logErr("Failed adjusting precedence of '%s': %v", spamAllowRuleName, err)
			return []string{fmt.Sprintf("Failed to reorder '%s': %v", spamAllowRuleName, err)}
		}
		msg := fmt.Sprintf("Adjusted rule precedence: moved '%s' from %d to %d (above spam-TLD at %d)",
			spamAllowRuleName, allowPrec, target, minSpamPrec)
		logInfo("%s", msg)
		return []string{msg}
	}

	allowTarget := maxDNSPrec + 50
	if err := setPrec(allowIdx, allowTarget); err != nil {
		logErr("Failed relocating '%s': %v", spamAllowRuleName, err)
		return []string{fmt.Sprintf("Failed to relocate '%s': %v", spamAllowRuleName, err)}
	}
	for offset, idx := range spamBlockIndices {
		if err := setPrec(idx, maxDNSPrec+100+int64(offset*10)); err != nil {
			logErr("Failed relocating '%s': %v", existingRules[idx].Name, err)
			return []string{fmt.Sprintf("Failed to relocate '%s': %v", existingRules[idx].Name, err)}
		}
	}
	msg := fmt.Sprintf("Adjusted rule precedence: placed '%s' (%d) above spam-TLD rule(s) (%d+)",
		spamAllowRuleName, allowTarget, maxDNSPrec+100)
	logInfo("%s", msg)
	return []string{msg}
}

func detachListsFromRules(cf *cloudflareAPI, listIDs []string, existingRules *[]gatewayRule) ([]gatewayRule, error) {
	if len(listIDs) == 0 {
		return nil, nil
	}
	var snapshots []gatewayRule
	detachedAny := false
	missingIDs := make(map[string]struct{})

	rules := *existingRules
	for i := range rules {
		rule := &rules[i]
		if !slices.ContainsFunc(listIDs, func(id string) bool { return clauseReferencesID(rule.Traffic, id) }) {
			continue
		}
		remaining, hasRemaining := stripListsFromTraffic(rule.Traffic, listIDs)
		newTraffic, newEnabled := dummyTrafficExpression, false
		if hasRemaining {
			newTraffic, newEnabled = remaining, rule.Enabled
		}

		_, err := cf.updateRule(rule.ID, buildRuleUpdatePayload(*rule, newEnabled, newTraffic))
		if err != nil && hasRemaining && strings.Contains(err.Error(), "HTTP 400") {
			logWarn("In-place detach rejected for '%s'; falling back to full detach.", rule.Name)
			newTraffic, newEnabled = dummyTrafficExpression, false
			_, err = cf.updateRule(rule.ID, buildRuleUpdatePayload(*rule, false, dummyTrafficExpression))
		}
		if err != nil {
			if strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "1102") {
				missingIDs[rule.ID] = struct{}{}
				continue
			}
			return snapshots, fmt.Errorf("detach lists from rule %s: %w", rule.Name, err)
		}
		snapshots = append(snapshots, rule.clone())
		rule.Traffic, rule.Enabled = newTraffic, newEnabled
		detachedAny = true
	}

	if len(missingIDs) > 0 {
		*existingRules = slices.DeleteFunc(rules, func(r gatewayRule) bool {
			_, missing := missingIDs[r.ID]
			return missing
		})
	}
	if detachedAny {
		time.Sleep(2 * time.Second)
	}
	return snapshots, nil
}

func restoreDetachedRules(cf *cloudflareAPI, snapshots []gatewayRule, deletedListIDs []string) {
	if len(snapshots) == 0 {
		return
	}
	logWarn("Restoring %d detached rule(s) after failure...", len(snapshots))
	for _, rule := range snapshots {
		traffic := rule.Traffic
		if len(deletedListIDs) > 0 {
			var ok bool
			if traffic, ok = stripListsFromTraffic(rule.Traffic, deletedListIDs); !ok {
				continue
			}
		}
		if _, err := cf.updateRule(rule.ID, buildRuleUpdatePayload(rule, rule.Enabled, traffic)); err != nil {
			logErr("Failed restoring rule '%s': %v", rule.Name, err)
		}
	}
}

func deleteListWithRetry(cf *cloudflareAPI, item gatewayList, existingRules *[]gatewayRule) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := cf.deleteList(item.ID)
		if err == nil || strings.Contains(err.Error(), "HTTP 404") {
			logInfo("Removed list: %s (%s)", item.Name, item.ID)
			return nil
		}
		if strings.Contains(err.Error(), "HTTP 400") && strings.Contains(err.Error(), "in use at gateway policies") && attempt < 2 {
			_, _ = detachListsFromRules(cf, []string{item.ID}, existingRules)
			time.Sleep(time.Duration((1<<attempt)+1)*time.Second + jitterMs(500))
			continue
		}
		return err
	}
	return fmt.Errorf("failed deleting list %s (%s)", item.Name, item.ID)
}

func scrubOrphanRules(cf *cloudflareAPI, cfg *appConfig, keepNames map[string]struct{}, existingRules *[]gatewayRule) int {
	deleted := make(map[string]struct{})
	for _, r := range *existingRules {
		if cfg.isProtectedRule(r.Name) || !containsAny(r.Name, cfg.ScrubTargets) {
			continue
		}
		if _, keep := keepNames[r.Name]; keep {
			continue
		}
		if err := cf.deleteRule(r.ID); err != nil {
			logErr("Rule cleanup error (%s): %v", r.Name, err)
		} else {
			logInfo("Removed orphaned rule: %s", r.Name)
			deleted[r.ID] = struct{}{}
		}
	}
	if len(deleted) > 0 {
		*existingRules = slices.DeleteFunc(*existingRules, func(r gatewayRule) bool {
			_, del := deleted[r.ID]
			return del
		})
	}
	return len(deleted)
}

func deleteListsBatched(cf *cloudflareAPI, lists []gatewayList, existingRules *[]gatewayRule) ([]gatewayRule, []string, error) {
	if len(lists) == 0 {
		return nil, nil, nil
	}
	ids := make([]string, len(lists))
	for i, l := range lists {
		ids[i] = l.ID
	}
	snapshots, err := detachListsFromRules(cf, ids, existingRules)
	if err != nil {
		return nil, nil, err
	}
	deleted := make([]string, 0, len(lists))
	for _, l := range lists {
		if err := deleteListWithRetry(cf, l, existingRules); err != nil {
			restoreDetachedRules(cf, snapshots, deleted)
			return nil, nil, err
		}
		deleted = append(deleted, l.ID)
	}
	return snapshots, deleted, nil
}

// ---------- Cross-Policy Sync Pool & Metrics ----------

type policySyncStats struct {
	Name, Prefix, Type, Status, RuleAction               string
	Priority, Entries, Deduped, Trimmed                  int
	ListsTotal, ListsCreated, ListsUpdated, ListsSkipped int
	Trimmable                                            bool
}

func syncAllPolicies(
	cf *cloudflareAPI,
	cfg *appConfig,
	existingLists []gatewayList,
	existingRules *[]gatewayRule,
	sets []compiledPolicy,
	tldExpr string,
	preservedListIDs, preservedRuleNames map[string]struct{},
	standaloneRules []string,
) (allActiveIDs, allSurplusIDs, allActiveRules []string, stats []policySyncStats, err error) {
	const (
		chunkNone = iota
		chunkSkipped
		chunkUpdated
		chunkCreated
	)

	allActiveRules = slices.Clone(standaloneRules)
	for id := range preservedListIDs {
		allActiveIDs = append(allActiveIDs, id)
	}
	for name := range preservedRuleNames {
		allActiveRules = append(allActiveRules, name)
	}

	type dirtyChunk struct {
		pIdx, cIdx                       int
		targetID, name, rawHash, listTyp string
		chunk                            []string
	}

	stats = make([]policySyncStats, len(sets))
	chunkIDs := make([][]string, len(sets))
	chunkOps := make([][]int, len(sets))
	var dirty []dirtyChunk

	// Phase 1: Hash all chunks across all policies and skip unchanged ones upfront
	for pIdx, cp := range sets {
		p := cp.Policy
		stats[pIdx] = policySyncStats{
			Name: p.Name, Prefix: p.Prefix, Type: p.resolvedType(),
			Priority: cp.Priority, Trimmable: cp.Trimmable, Status: "synced",
			Entries: len(cp.Entries), Deduped: cp.DedupedCount, Trimmed: cp.TrimmedCount, RuleAction: "unchanged",
		}
		if p.Prefix == "" || p.Name == "" {
			stats[pIdx].Status = "inactive"
			continue
		}

		type indexedList struct {
			idx  int
			list gatewayList
		}
		var matched []indexedList
		for _, l := range existingLists {
			if idx, ok := parseChunkIndex(l.Name, p.Prefix); ok {
				matched = append(matched, indexedList{idx: idx, list: l})
			}
		}
		slices.SortFunc(matched, func(a, b indexedList) int { return cmp.Compare(a.idx, b.idx) })

		chunkIDs[pIdx] = make([]string, len(cp.Chunks))
		chunkOps[pIdx] = make([]int, len(cp.Chunks))
		pType := p.resolvedType()

		for cIdx, chunk := range cp.Chunks {
			name := fmt.Sprintf("%s %03d", p.Prefix, cIdx+1)
			rawHash := hashChunk(chunk)
			if cIdx < len(matched) && chunkMatchesRemote(matched[cIdx].list, name, rawHash, len(chunk)) {
				chunkIDs[pIdx][cIdx], chunkOps[pIdx][cIdx] = matched[cIdx].list.ID, chunkSkipped
				continue
			}
			targetID := ""
			if cIdx < len(matched) {
				targetID = matched[cIdx].list.ID
			}
			dirty = append(dirty, dirtyChunk{
				pIdx: pIdx, cIdx: cIdx, targetID: targetID, name: name, rawHash: rawHash, listTyp: pType, chunk: chunk,
			})
		}
		for _, m := range matched[min(len(cp.Chunks), len(matched)):] {
			allSurplusIDs = append(allSurplusIDs, m.list.ID)
		}
	}

	// Phase 2: Drain all dirty list writes across policies in one shared pool
	if len(dirty) > 0 {
		sem := make(chan struct{}, min(cfg.MaxWorkers, 3))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var firstErr error
		var errMu sync.Mutex
		var wg sync.WaitGroup

		for _, dc := range dirty {
			wg.Add(1)
			go func(dc dirtyChunk) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				cur := slices.Clone(dc.chunk)
				for attempt := 0; attempt < maxLabelPurgeAttempts; attempt++ {
					if len(cur) == 0 {
						return
					}
					desc := dc.rawHash
					if len(cur) != len(dc.chunk) {
						desc = fmt.Sprintf("%s:%d", dc.rawHash, len(cur))
					}

					var id string
					var wErr error
					var op int
					if dc.targetID != "" {
						id = dc.targetID
						wErr = cf.updateList(ctx, id, dc.name, cur, desc)
						op = chunkUpdated
						if wErr == nil {
							logInfo("Updated %s (%d %s items)", dc.name, len(cur), strings.ToLower(dc.listTyp))
						}
					} else {
						id, wErr = cf.createList(ctx, dc.name, cur, dc.listTyp, desc)
						op = chunkCreated
						if wErr == nil {
							logInfo("Created %s (%d %s items)", dc.name, len(cur), strings.ToLower(dc.listTyp))
						}
					}
					if wErr == nil {
						chunkIDs[dc.pIdx][dc.cIdx], chunkOps[dc.pIdx][dc.cIdx] = id, op
						return
					}
					if attempt+1 < maxLabelPurgeAttempts {
						if m := rejectedEntryRe.FindStringSubmatch(wErr.Error()); len(m) > 1 {
							bad := strings.ToLower(m[1])
							before := len(cur)
							cur = slices.DeleteFunc(cur, func(d string) bool {
								dl := strings.ToLower(d)
								return dl == bad || slices.Contains(strings.Split(dl, "."), bad)
							})
							if len(cur) < before {
								logWarn("Purged rejected entry '%s' from %s (%d removed) and retrying...", bad, dc.name, before-len(cur))
								continue
							}
						}
					}
					logErr("Error syncing %s (chunk size: %d): %v", dc.name, len(cur), wErr)
					errMu.Lock()
					if firstErr == nil {
						firstErr = wErr
						cancel()
					}
					errMu.Unlock()
					return
				}
			}(dc)
		}
		wg.Wait()
		if firstErr != nil {
			return nil, nil, nil, nil, firstErr
		}
	}

	// Phase 3: Reconcile firewall rules for every policy
	for pIdx, cp := range sets {
		if stats[pIdx].Status == "inactive" {
			continue
		}
		p := cp.Policy
		pType := p.resolvedType()

		pActiveIDs := make([]string, 0, len(chunkIDs[pIdx]))
		for i, id := range chunkIDs[pIdx] {
			if id != "" {
				pActiveIDs = append(pActiveIDs, id)
			}
			switch chunkOps[pIdx][i] {
			case chunkSkipped:
				stats[pIdx].ListsSkipped++
			case chunkUpdated:
				stats[pIdx].ListsUpdated++
			case chunkCreated:
				stats[pIdx].ListsCreated++
			}
		}
		stats[pIdx].ListsTotal = len(pActiveIDs)
		allActiveIDs = append(allActiveIDs, pActiveIDs...)

		var listItems []string
		fieldExpr := "any(dns.domains[*] in $%s)"
		if pType == "IP" {
			fieldExpr = "any(dns.resolved_ips[*] in $%s)"
		}
		for _, lid := range pActiveIDs {
			listItems = append(listItems, fmt.Sprintf(fieldExpr, lid))
		}
		if pType != "IP" && tldExpr != "" && p.UseSpamTLD {
			listItems = append(listItems, fmt.Sprintf("(%s)", tldExpr))
		}
		if catExpr := compileCategoryExpression(p); catExpr != "" {
			listItems = append(listItems, catExpr)
		}

		rules := *existingRules
		ruleIdx := slices.IndexFunc(rules, func(r gatewayRule) bool { return r.Name == p.Name })

		if len(listItems) == 0 {
			stats[pIdx].Status = "inactive"
			if ruleIdx >= 0 {
				if dErr := cf.deleteRule(rules[ruleIdx].ID); dErr != nil {
					logErr("Failed deleting inactive rule %s: %v", p.Name, dErr)
				} else {
					logInfo("Removed inactive firewall rule: %s", p.Name)
					*existingRules = slices.Delete(rules, ruleIdx, ruleIdx+1)
					stats[pIdx].RuleAction = "deleted"
				}
			}
			continue
		}

		cond := p.effectiveIdentity(cfg)
		trafficExpr, identityExpr := strings.Join(listItems, " or "), ""
		if cond != "" {
			if !strings.Contains(cond, "dns.") {
				identityExpr = cond
			} else {
				wrapped := make([]string, len(listItems))
				for i, item := range listItems {
					wrapped[i] = fmt.Sprintf("(%s and %s)", cond, item)
				}
				trafficExpr = strings.Join(wrapped, " or ")
			}
		}

		var ruleEnabled bool
		switch {
		case p.Enabled != nil && !*p.Enabled:
			ruleEnabled = false
		case cfg.AutoEnableRules:
			ruleEnabled = true
		case ruleIdx >= 0:
			ruleEnabled = rules[ruleIdx].Enabled
		case p.Enabled != nil:
			ruleEnabled = *p.Enabled
		}

		blockPage := ptrOr(p.BlockPageEnabled, cfg.BlockPageEnabled)
		ipCat, action := p.IPCategories, p.resolvedAction()

		settings := map[string]any{}
		if ruleIdx >= 0 && rules[ruleIdx].RuleSettings != nil {
			for k, v := range rules[ruleIdx].RuleSettings {
				settings[k] = v
			}
		}
		settings["block_page_enabled"], settings["ip_categories"] = blockPage, ipCat

		payload := map[string]any{
			"name": p.Name, "action": action, "enabled": ruleEnabled,
			"filters": []string{"dns"}, "traffic": trafficExpr, "rule_settings": settings,
		}
		if identityExpr != "" {
			payload["identity"] = identityExpr
		}

		if ruleIdx >= 0 {
			r := rules[ruleIdx]
			for k, raw := range map[string]json.RawMessage{
				"precedence": r.Precedence, "description": r.Description,
				"schedule": r.Schedule, "device_posture": r.DevicePosture,
			} {
				if isNonNullRaw(raw) {
					payload[k] = raw
				}
			}
			oldBP, _ := r.RuleSettings["block_page_enabled"].(bool)
			oldIPCat, _ := r.RuleSettings["ip_categories"].(bool)
			if r.Traffic != trafficExpr || r.Identity != identityExpr || r.Enabled != ruleEnabled ||
				r.Action != action || oldBP != blockPage || oldIPCat != ipCat {
				updated, uErr := cf.updateRule(r.ID, payload)
				if uErr != nil {
					return nil, nil, nil, nil, uErr
				}
				if updated != nil {
					rules[ruleIdx] = *updated
				}
				stats[pIdx].RuleAction = "updated"
				logInfo("Updated firewall rule: %s (enabled=%t, block_page=%t, ip_categories=%t)",
					p.Name, ruleEnabled, blockPage, ipCat)
			}
		} else {
			created, cErr := cf.createRule(payload)
			if cErr != nil {
				return nil, nil, nil, nil, cErr
			}
			if created != nil {
				*existingRules = append(rules, *created)
			}
			stats[pIdx].RuleAction = "created"
			logInfo("Created firewall rule: %s (enabled=%t, block_page=%t, ip_categories=%t)",
				p.Name, ruleEnabled, blockPage, ipCat)
		}
		allActiveRules = append(allActiveRules, p.Name)
	}

	return allActiveIDs, allSurplusIDs, allActiveRules, stats, nil
}

func syncStandalonePolicies(cf *cloudflareAPI, cfg *appConfig, existingRules []gatewayRule) []string {
	var synced []string
	for name, val := range cfg.Raw.GatewayPolicies {
		desired, ok := val.(bool)
		if !ok {
			continue
		}
		idx := slices.IndexFunc(existingRules, func(r gatewayRule) bool { return r.Name == name })
		if idx < 0 {
			continue
		}
		synced = append(synced, name)
		matched := &existingRules[idx]
		if !cfg.AutoEnableRules && !matched.Enabled && desired {
			continue
		}
		if matched.Enabled != desired {
			if _, err := cf.updateRule(matched.ID, buildRuleUpdatePayload(*matched, desired, matched.Traffic)); err != nil {
				logErr("Failed updating standalone policy %s: %v", name, err)
			} else {
				matched.Enabled = desired
				logInfo("Updated standalone policy: %s -> enabled=%t", name, desired)
			}
		}
	}
	return synced
}

func reclaimStaleResources(
	cf *cloudflareAPI,
	cfg *appConfig,
	compiled []compiledPolicy,
	tldExpr string,
	preservedListIDs, preservedRuleNames map[string]struct{},
	existingLists *[]gatewayList,
	existingRules *[]gatewayRule,
) ([]gatewayRule, []string, error) {
	expectedRules := make(map[string]struct{}, len(preservedRuleNames)+len(compiled))
	for k := range preservedRuleNames {
		expectedRules[k] = struct{}{}
	}
	keepIDs := make(map[string]struct{}, len(preservedListIDs))
	for k := range preservedListIDs {
		keepIDs[k] = struct{}{}
	}

	for _, cp := range compiled {
		if len(cp.Chunks) > 0 || (tldExpr != "" && cp.Policy.UseSpamTLD) || compileCategoryExpression(cp.Policy) != "" {
			expectedRules[cp.Policy.Name] = struct{}{}
		}
		type indexedList struct {
			idx int
			id  string
		}
		var matched []indexedList
		for _, l := range *existingLists {
			if idx, ok := parseChunkIndex(l.Name, cp.Policy.Prefix); ok {
				matched = append(matched, indexedList{idx: idx, id: l.ID})
			}
		}
		slices.SortFunc(matched, func(a, b indexedList) int { return cmp.Compare(a.idx, b.idx) })
		for _, m := range matched[:min(len(cp.Chunks), len(matched))] {
			keepIDs[m.id] = struct{}{}
		}
	}

	if scrubOrphanRules(cf, cfg, expectedRules, existingRules) > 0 {
		time.Sleep(2 * time.Second)
	}

	var stale []gatewayList
	for _, l := range *existingLists {
		if _, keep := keepIDs[l.ID]; !keep && cfg.isManagedList(l.Name) {
			stale = append(stale, l)
		}
	}
	if len(stale) == 0 {
		return nil, nil, nil
	}
	logInfo("Pre-reclaiming %d stale/surplus list(s) before sync...", len(stale))
	snapshots, deletedIDs, err := deleteListsBatched(cf, stale, existingRules)
	if err != nil {
		return nil, nil, err
	}
	delSet := make(map[string]struct{}, len(deletedIDs))
	for _, id := range deletedIDs {
		delSet[id] = struct{}{}
	}
	*existingLists = slices.DeleteFunc(*existingLists, func(l gatewayList) bool {
		_, del := delSet[l.ID]
		return del
	})
	return snapshots, deletedIDs, nil
}

func cleanupOrphans(
	cf *cloudflareAPI,
	cfg *appConfig,
	existingLists []gatewayList,
	existingRules *[]gatewayRule,
	activeIDs, surplusIDs, activeRules []string,
) error {
	keepRules := make(map[string]struct{}, len(activeRules))
	for _, r := range activeRules {
		keepRules[r] = struct{}{}
	}
	if scrubOrphanRules(cf, cfg, keepRules, existingRules) > 0 || len(surplusIDs) > 0 {
		time.Sleep(2 * time.Second)
	}

	activeSet, surplusSet := make(map[string]struct{}, len(activeIDs)), make(map[string]struct{}, len(surplusIDs))
	for _, id := range activeIDs {
		activeSet[id] = struct{}{}
	}
	for _, id := range surplusIDs {
		surplusSet[id] = struct{}{}
	}

	var toDelete []gatewayList
	for _, l := range existingLists {
		_, isSurplus := surplusSet[l.ID]
		_, isActive := activeSet[l.ID]
		if isSurplus || (!isActive && cfg.isManagedList(l.Name)) {
			toDelete = append(toDelete, l)
		}
	}
	_, _, err := deleteListsBatched(cf, toDelete, existingRules)
	return err
}

func filterPolicyIncludes(policies []policyConfig, keep func(string) bool) {
	for i := range policies {
		policies[i].Include = slices.DeleteFunc(policies[i].Include, func(s string) bool { return !keep(s) })
	}
}

// ---------- GitHub Actions Step Summary ----------

func writeStepSummary(
	duration time.Duration,
	relStatus string,
	relCount, feedsOK, totalItems, totalQuota, managedLists, unmanagedLists int,
	failedFeeds, warnings []string,
	policyStats []policySyncStats,
) {
	summaryPath := strings.TrimSpace(os.Getenv("GITHUB_STEP_SUMMARY"))
	if summaryPath == "" {
		return
	}
	created, updated, skipped := 0, 0, 0
	for _, ps := range policyStats {
		created += ps.ListsCreated
		updated += ps.ListsUpdated
		skipped += ps.ListsSkipped
	}
	skipPct := 100.0
	if ops := created + updated + skipped; ops > 0 {
		skipPct = float64(skipped) * 100.0 / float64(ops)
	}
	usedLists := managedLists + unmanagedLists

	var sb strings.Builder
	fmt.Fprintf(&sb, "## Cloudflare Gateway Sync Summary\n\n| Metric | Value |\n| :--- | :--- |\n")
	fmt.Fprintf(&sb, "| **Duration** | `%.2fs` |\n", duration.Seconds())
	fmt.Fprintf(&sb, "| **Relevance Cache** | `%s` (%d root domains) |\n", relStatus, relCount)
	fmt.Fprintf(&sb, "| **Item Quota** | `%d / %d` (%.1f%%) |\n", totalItems, totalQuota, float64(totalItems)*100.0/float64(max(totalQuota, 1)))
	fmt.Fprintf(&sb, "| **List Quota** | `%d / %d` (%.1f%% — %d managed, %d unmanaged) |\n",
		usedLists, maxCloudflareLists, float64(usedLists)*100.0/float64(maxCloudflareLists), managedLists, unmanagedLists)
	fmt.Fprintf(&sb, "| **List Writes** | `%d` created, `%d` updated, `%d` unchanged (%.1f%% skipped) |\n", created, updated, skipped, skipPct)
	fmt.Fprintf(&sb, "| **Upstream Feeds** | `%d` ok, `%d` failed |\n\n", feedsOK, len(failedFeeds))

	sb.WriteString("### Policies\n\n| Policy | Prio | Type | Mode | Status | Entries | Deduped | Trimmed | Lists (C/U/S) | Rule |\n| :--- | :---: | :---: | :---: | :---: | ---: | ---: | ---: | :---: | :---: |\n")
	for _, ps := range policyStats {
		mode := "protected"
		if ps.Trimmable {
			mode = "trimmable"
		}
		fmt.Fprintf(&sb, "| %s | %d | %s | `%s` | `%s` | %d | %d | %d | %d (%d/%d/%d) | `%s` |\n",
			ps.Name, ps.Priority, ps.Type, mode, ps.Status,
			ps.Entries, ps.Deduped, ps.Trimmed,
			ps.ListsTotal, ps.ListsCreated, ps.ListsUpdated, ps.ListsSkipped, ps.RuleAction)
	}
	if len(failedFeeds) > 0 || len(warnings) > 0 {
		sb.WriteString("\n### Warnings & Notices\n\n")
		for _, f := range failedFeeds {
			fmt.Fprintf(&sb, "- **Upstream feed failed (preserved live state):** `%s`\n", f)
		}
		for _, w := range warnings {
			fmt.Fprintf(&sb, "- %s\n", w)
		}
	}
	sb.WriteString("\n")

	if f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		_, _ = f.WriteString(sb.String())
		f.Close()
	}
}

// ---------- Main Orchestration ----------

func run() error {
	start := time.Now()
	configPath := flag.String("config", "config.toml", "Path to config.toml")
	forceRefresh := flag.Bool("force-refresh-relevance", false, "Force rebuild of relevance cache")
	strictFeeds := flag.Bool("strict", false, "Exit non-zero if any upstream feed fails")
	flag.Parse()

	cfg, err := loadConfig(*configPath, *forceRefresh, *strictFeeds)
	if err != nil {
		return err
	}
	cf := newCloudflareAPI(cfg)

	policyKeys := make([]string, 0, len(cfg.Raw.Policies))
	for k := range cfg.Raw.Policies {
		policyKeys = append(policyKeys, k)
	}
	slices.Sort(policyKeys)

	allPolicies := make([]policyConfig, 0, len(policyKeys)+1)
	spamTLDBlockNames := make(map[string]struct{})
	trimmableSources := make(map[string]struct{})
	useSpamTLDAny := false
	for _, k := range policyKeys {
		p := cfg.Raw.Policies[k]
		if p.UseSpamTLD {
			useSpamTLDAny = true
			if p.resolvedAction() != "allow" && p.Name != "" {
				spamTLDBlockNames[p.Name] = struct{}{}
			}
		}
		if p.isTrimmable() {
			for _, inc := range p.Include {
				trimmableSources[inc] = struct{}{}
			}
		}
		allPolicies = append(allPolicies, p)
	}

	domainSources := parseSources(cfg.Raw.Sources, false)
	ipSources := parseSources(cfg.Raw.IPSources, true)

	if useSpamTLDAny && cfg.Raw.SpamAllowSource != nil && cfg.Raw.SpamAllowSource.Name != "" {
		sa := cfg.Raw.SpamAllowSource
		allPolicies = append(allPolicies, policyConfig{
			Prefix: "L_AllowSpam", Name: spamAllowRuleName, Type: "DOMAIN", Action: "allow", Include: []string{sa.Name},
		})
		domainSources = append(domainSources, sourceSpec{
			Name: sa.Name, URLs: []string{sa.URL}, EnableRelevance: ptrOr(sa.Relevance, false),
		})
	}

	feedClient := newHTTPClient(90 * time.Second)
	needsRelevance := slices.ContainsFunc(domainSources, func(s sourceSpec) bool { return s.EnableRelevance })
	needsRelForSource := func(s sourceSpec) bool {
		if !needsRelevance {
			return false
		}
		_, inTrim := trimmableSources[s.Name]
		return s.EnableRelevance || inTrim
	}

	// Launch all independent startup I/O concurrently (CF lists/rules, Spam TLDs, IP feeds, non-relevance feeds)
	var (
		existingLists []gatewayList
		existingRules []gatewayRule
		listsErr      error
		rulesErr      error
		tldExpr       string
		spamTLDs      map[string]struct{}
		tldFailed     bool
		bgWG          sync.WaitGroup
	)
	bgWG.Add(2)
	go func() { defer bgWG.Done(); existingLists, listsErr = cf.getLists() }()
	go func() { defer bgWG.Done(); existingRules, rulesErr = cf.getRules() }()
	if cfg.Raw.TLD.URL != "" && useSpamTLDAny {
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			var tErr error
			if tldExpr, spamTLDs, tErr = fetchSpamTLDs(feedClient, cfg.Raw.TLD.URL); tErr != nil {
				logErr("Spam TLD feed failure: %v. Preserving TLD-dependent policies.", tErr)
				tldFailed = true
			}
		}()
	}

	type feedOutcome struct {
		name string
		feed fetchedFeed
		err  error
	}
	totalSources := len(domainSources) + len(ipSources)
	outcomes := make([]feedOutcome, totalSources)
	sem := make(chan struct{}, cfg.MaxWorkers)
	var feedWG sync.WaitGroup

	launchDomain := func(i int, spec sourceSpec, rel *relevanceSet) {
		feedWG.Add(1)
		go func() {
			defer feedWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			kept, fErr := fetchFeedSource(feedClient, spec, rel)
			if fErr == nil && len(kept) == 0 {
				fErr = fmt.Errorf("feed '%s' returned 0 valid domains", spec.Name)
			}
			outcomes[i] = feedOutcome{name: spec.Name, feed: fetchedFeed{Domains: kept}, err: fErr}
		}()
	}

	for i, spec := range domainSources {
		if !needsRelForSource(spec) {
			launchDomain(i, spec, nil)
		}
	}
	for j, spec := range ipSources {
		idx := len(domainSources) + j
		feedWG.Add(1)
		go func(idx int, spec sourceSpec) {
			defer feedWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			nets, fErr := fetchIPSource(feedClient, spec)
			if fErr == nil && len(nets) == 0 {
				fErr = fmt.Errorf("IP feed '%s' returned 0 valid subnets", spec.Name)
			}
			outcomes[idx] = feedOutcome{name: spec.Name, feed: fetchedFeed{IsIP: true, IPs: nets}, err: fErr}
		}(idx, spec)
	}

	var relSet *relevanceSet
	relevanceStatus, relevanceCount := "unused", 0
	if needsRelevance {
		if relSet, relevanceStatus, err = resolveRelevanceDataset(feedClient, cfg); err != nil {
			feedWG.Wait()
			bgWG.Wait()
			return err
		}
		relevanceCount = relSet.len()
		for i, spec := range domainSources {
			if needsRelForSource(spec) {
				launchDomain(i, spec, relSet)
			}
		}
	}

	feedWG.Wait()
	relSet = nil
	runtime.GC()
	bgWG.Wait()

	if listsErr != nil {
		return listsErr
	}
	if rulesErr != nil {
		return rulesErr
	}

	fetched := make(map[string]fetchedFeed, totalSources)
	failedFeeds := make(map[string]struct{})
	var failedFeedList []string
	for _, o := range outcomes {
		if o.err != nil {
			logErr("Upstream feed '%s' failed: %v. Preserving dependent policies.", o.name, o.err)
			failedFeeds[o.name] = struct{}{}
			failedFeedList = append(failedFeedList, fmt.Sprintf("%s (%v)", o.name, o.err))
		} else {
			fetched[o.name] = o.feed
		}
	}
	if tldFailed {
		failedFeedList = append(failedFeedList, "Spam TLD Feed")
	}
	if totalSources > 0 && len(fetched) == 0 {
		return fmt.Errorf("all %d upstream feeds failed; aborting", totalSources)
	}

	var activePolicies, preservedPolicies []policyConfig
	for _, p := range allPolicies {
		hasBadDep := slices.ContainsFunc(p.Include, func(s string) bool { _, b := failedFeeds[s]; return b }) ||
			slices.ContainsFunc(p.Exclude, func(s string) bool { _, b := failedFeeds[s]; return b })
		if hasBadDep || (p.UseSpamTLD && tldFailed) {
			logWarn("Preserving Cloudflare state for '%s' due to feed failure.", p.Name)
			preservedPolicies = append(preservedPolicies, p)
		} else {
			activePolicies = append(activePolicies, p)
		}
	}

	preservedListIDs, preservedRuleNames := make(map[string]struct{}), make(map[string]struct{})
	preservedItems := 0
	preservedStats := make([]policySyncStats, 0, len(preservedPolicies))
	for _, p := range preservedPolicies {
		preservedRuleNames[p.Name] = struct{}{}
		pLists, pItems := 0, 0
		for _, l := range existingLists {
			if _, ok := parseChunkIndex(l.Name, p.Prefix); ok {
				preservedListIDs[l.ID] = struct{}{}
				pLists++
				if l.Count != nil {
					pItems += int(*l.Count)
				}
			}
		}
		preservedItems += pItems
		preservedStats = append(preservedStats, policySyncStats{
			Name: p.Name, Prefix: p.Prefix, Type: p.resolvedType(), Priority: p.resolvedPriority(cfg),
			Trimmable: p.isTrimmable(), Status: "preserved", Entries: pItems, ListsTotal: pLists, RuleAction: "preserved",
		})
	}

	unmanagedLists, currentManagedItems := 0, 0
	for _, l := range existingLists {
		if cfg.isManagedList(l.Name) {
			if l.Count != nil {
				currentManagedItems += int(*l.Count)
			}
		} else {
			unmanagedLists++
		}
	}

	maxActiveLists := max(maxCloudflareLists-unmanagedLists-len(preservedListIDs), 0)
	activeQuota := max(cfg.TotalQuota-preservedItems, 0)
	hasActiveSpamTLD := useSpamTLDAny && !tldFailed
	var summaryWarnings []string

	shedTiers := []struct {
		label string
		drop  func(string) bool
	}{
		{"OISD NSFW", func(l string) bool { return strings.Contains(l, "oisd") && strings.Contains(l, "nsfw") }},
		{"TIF IPs", func(l string) bool { return strings.Contains(l, "tif") && strings.Contains(l, "ip") }},
		{"TIF domain feeds", func(l string) bool { return strings.Contains(l, "tif") }},
	}

	compileAndFit := func(pols []policyConfig, elists []gatewayList) ([]compiledPolicy, int, int, error) {
		compiled, guardWarns := buildPolicySets(cfg, pols, fetched, spamTLDs, hasActiveSpamTLD)
		if len(guardWarns) > 0 {
			summaryWarnings = append(summaryWarnings, fmt.Sprintf("Config never_block stripped %d domain(s): %s",
				len(guardWarns), strings.Join(guardWarns, ", ")))
		}
		summaryWarnings = append(summaryWarnings, trimByRank(compiled, activeQuota, maxActiveLists, cfg.MaxListSize)...)
		entries, minLists := sumMinCapacity(compiled, cfg.MaxListSize)

		for _, tier := range shedTiers {
			if entries <= activeQuota && minLists <= maxActiveLists {
				break
			}
			msg := fmt.Sprintf("Capacity exceeded (%d/%d entries, %d/%d min lists); shedding %s...",
				entries, activeQuota, minLists, maxActiveLists, tier.label)
			logWarn("%s", msg)
			summaryWarnings = append(summaryWarnings, msg)
			filterPolicyIncludes(pols, func(inc string) bool { return !tier.drop(strings.ToLower(inc)) })
			compiled, _ = buildPolicySets(cfg, pols, fetched, spamTLDs, hasActiveSpamTLD)
			trimByRank(compiled, activeQuota, maxActiveLists, cfg.MaxListSize)
			entries, minLists = sumMinCapacity(compiled, cfg.MaxListSize)
		}
		if entries > activeQuota || minLists > maxActiveLists {
			return nil, 0, 0, fmt.Errorf("capacity exceeded after all tiers (%d/%d entries, %d/%d lists)",
				entries, activeQuota, minLists, maxActiveLists)
		}
		return compiled, entries, assignHashBuckets(compiled, elists, cfg.MaxListSize, maxActiveLists), nil
	}

	compiled, activeEntries, totalChunks, err := compileAndFit(activePolicies, existingLists)
	if err != nil {
		return err
	}
	logInfo("Cloudflare lists: %d total (%d unmanaged, %d preserved, %d live items). Syncing %d list(s)...",
		len(existingLists), unmanagedLists, len(preservedListIDs), currentManagedItems, totalChunks)

	standaloneRules := syncStandalonePolicies(cf, cfg, existingRules)
	reclaimSnapshots, reclaimedIDs, err := reclaimStaleResources(
		cf, cfg, compiled, tldExpr, preservedListIDs, preservedRuleNames, &existingLists, &existingRules,
	)
	if err != nil {
		return err
	}

	allActiveIDs, allSurplusIDs, allActiveRules, policyStats, syncErr := syncAllPolicies(
		cf, cfg, existingLists, &existingRules, compiled, tldExpr, preservedListIDs, preservedRuleNames, standaloneRules,
	)
	if syncErr != nil {
		if strings.Contains(syncErr.Error(), "Maximum number of lists reached") || strings.Contains(syncErr.Error(), "2017") {
			logErr("Cloudflare 300-list limit hit; running emergency reclamation and rebuild...")
			summaryWarnings = append(summaryWarnings, "Emergency 300-list limit recovery triggered.")
			if existingLists, err = cf.getLists(); err != nil {
				return err
			}
			if existingRules, err = cf.getRules(); err != nil {
				return err
			}
			var reclaimable []gatewayList
			for _, l := range existingLists {
				if _, pres := preservedListIDs[l.ID]; !pres && cfg.isManagedList(l.Name) {
					reclaimable = append(reclaimable, l)
				}
			}
			snaps, delIDs, delErr := deleteListsBatched(cf, reclaimable, &existingRules)
			if delErr != nil {
				return delErr
			}
			time.Sleep(3 * time.Second)
			filterPolicyIncludes(activePolicies, func(inc string) bool {
				l := strings.ToLower(inc)
				return !(strings.Contains(l, "oisd") && strings.Contains(l, "nsfw")) && !strings.Contains(l, "tif")
			})
			if existingLists, err = cf.getLists(); err != nil {
				restoreDetachedRules(cf, snaps, delIDs)
				return err
			}
			if existingRules, err = cf.getRules(); err != nil {
				restoreDetachedRules(cf, snaps, delIDs)
				return err
			}
			if compiled, activeEntries, totalChunks, err = compileAndFit(activePolicies, existingLists); err != nil {
				restoreDetachedRules(cf, snaps, delIDs)
				return err
			}
			if allActiveIDs, allSurplusIDs, allActiveRules, policyStats, err = syncAllPolicies(
				cf, cfg, existingLists, &existingRules, compiled, tldExpr, preservedListIDs, preservedRuleNames, standaloneRules,
			); err != nil {
				restoreDetachedRules(cf, snaps, delIDs)
				return err
			}
		} else {
			restoreDetachedRules(cf, reclaimSnapshots, reclaimedIDs)
			return syncErr
		}
	}

	if err := cleanupOrphans(cf, cfg, existingLists, &existingRules, allActiveIDs, allSurplusIDs, allActiveRules); err != nil {
		return err
	}
	summaryWarnings = append(summaryWarnings, ensureSpamAllowPrecedence(cf, spamTLDBlockNames, existingRules)...)

	policyStats = append(policyStats, preservedStats...)
	slices.SortFunc(policyStats, func(a, b policySyncStats) int {
		if c := cmp.Compare(a.Priority, b.Priority); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	created, updated, skipped := 0, 0, 0
	for _, ps := range policyStats {
		created += ps.ListsCreated
		updated += ps.ListsUpdated
		skipped += ps.ListsSkipped
	}
	elapsed := time.Since(start)
	totalLive := activeEntries + preservedItems
	logInfo("Sync finished in %.2fs | relevance=%s | lists=%d (C:%d U:%d S:%d) | items=%d/%d | feeds_ok=%d failed=%d",
		elapsed.Seconds(), relevanceStatus, len(allActiveIDs), created, updated, skipped,
		totalLive, cfg.TotalQuota, len(fetched), len(failedFeedList))

	writeStepSummary(elapsed, relevanceStatus, relevanceCount, len(fetched), totalLive, cfg.TotalQuota,
		len(allActiveIDs), unmanagedLists, failedFeedList, summaryWarnings, policyStats)

	if cfg.StrictFeeds && len(failedFeedList) > 0 {
		return fmt.Errorf("--strict enabled and %d upstream feed(s) failed", len(failedFeedList))
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		logErr("%v", err)
		os.Exit(1)
	}
}
