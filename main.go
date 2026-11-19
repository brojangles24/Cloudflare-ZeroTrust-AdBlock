package main

import (
	"archive/zip"
	"bufio"
	"bytes"
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
	cacheMagicV1           = "RELCAC01"
	cacheMagicV2           = "RELCAC02"
	dummyTrafficExpression = `any(dns.domains[*] in {"invalid.local.blocklist.temp"})`
)

var defaultProtectedRules = []string{
	"IoT Bypass",
	"Custom",
	"Keywords",
	"SafeSearch",
	"Global Blocklist",
	"Global Bypass",
	"Block IoT Network",
	"YouTube Restricted",
}

type topListSpec struct {
	URL         string
	Col         int
	SkipHeader  bool
	Compression string
}

var defaultTopLists = []topListSpec{
	{URL: "https://tranco-list.eu/top-1m.csv.zip", Col: 1, SkipHeader: false, Compression: "zip"},
	{URL: "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", Col: 0, SkipHeader: true, Compression: "gzip"},
	{URL: "https://downloads.majestic.com/majestic_million.csv", Col: 2, SkipHeader: true, Compression: "raw"},
	{URL: "https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip", Col: 1, SkipHeader: true, Compression: "zip"},
	{URL: "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", Col: 1, SkipHeader: false, Compression: "zip"},
}

var (
	rejectedEntryRe = regexp.MustCompile(`invalid (?:label|domain|value) ["']?([a-zA-Z0-9_\-\.:/]+?)["'\s]`)
	reservedV4Nets  = mustParsePrefixes([]string{
		"0.0.0.0/8",       // RFC 1122 / Unspecified
		"10.0.0.0/8",      // RFC 1918
		"100.64.0.0/10",   // RFC 6598 CGNAT (Tailscale / WARP)
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"172.16.0.0/12",   // RFC 1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.168.0.0/16",  // RFC 1918
		"198.18.0.0/15",   // Benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // Multicast
		"240.0.0.0/4",     // Reserved + Broadcast
	})
	reservedV6Nets = mustParsePrefixes([]string{
		"::/128",
		"::1/128",
		"fc00::/7",      // Unique local
		"fe80::/10",     // Link-local
		"ff00::/8",      // Multicast
		"2001:db8::/32", // Documentation
	})
)

func mustParsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

func logInfo(format string, args ...any) { fmt.Printf("[INFO] "+format+"\n", args...) }
func logWarn(format string, args ...any) { fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", args...) }
func logErr(format string, args ...any)  { fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...) }

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

// ---------- Typed Configuration ----------

type settingsConfig struct {
	MaxWorkers               *int     `toml:"max_workers"`
	MaxListSize              *int     `toml:"max_list_size"`
	TotalQuota               *int     `toml:"total_quota"`
	RequestTimeout           any      `toml:"request_timeout"`
	ScrubTargets             []string `toml:"scrub_targets"`
	AutoEnableRules          *bool    `toml:"auto_enable_rules"`
	BlockPageEnabled         *bool    `toml:"block_page_enabled"`
	BaseFeed                 string   `toml:"base_feed"`
	BaseExemptPrefixes       []string `toml:"base_exempt_prefixes"`
	ProtectedRules           []string `toml:"protected_rules"`
	UnmanagedListKeywords    []string `toml:"unmanaged_list_keywords"`
	RelevanceCacheDir        string   `toml:"relevance_cache_dir"`
	RelevanceMinRefreshHours *int64   `toml:"relevance_min_refresh_hours"`
	RelevanceTTLDays         *int64   `toml:"relevance_ttl_days"`
}

type policyConfig struct {
	Prefix             string   `toml:"prefix"`
	Name               string   `toml:"name"`
	Type               string   `toml:"type"`
	Action             string   `toml:"action"`
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

func (p policyConfig) clone() policyConfig {
	cp := p
	cp.Include = slices.Clone(p.Include)
	cp.Exclude = slices.Clone(p.Exclude)
	cp.Domains = slices.Clone(p.Domains)
	cp.SecurityCategories = slices.Clone(p.SecurityCategories)
	cp.ContentCategories = slices.Clone(p.ContentCategories)
	cp.AppIDs = slices.Clone(p.AppIDs)
	return cp
}

type tldConfig struct {
	URL string `toml:"url"`
}

type spamAllowSourceConfig struct {
	Name      string `toml:"name"`
	URL       string `toml:"url"`
	Relevance *bool  `toml:"relevance"`
}

type rawConfig struct {
	Settings        settingsConfig          `toml:"settings"`
	Sources         map[string]any          `toml:"sources"`
	IPSources       map[string]any          `toml:"ip_sources"`
	Policies        map[string]policyConfig `toml:"policies"`
	TLD             tldConfig               `toml:"tld"`
	SpamAllowSource *spamAllowSourceConfig  `toml:"spam_allow_source"`
	GatewayPolicies map[string]any          `toml:"gateway_policies"`
}

type appConfig struct {
	APIToken                string
	AccountID               string
	TargetIdentity          string
	MaxWorkers              int
	MaxListSize             int
	TotalQuota              int
	Timeout                 time.Duration
	ScrubTargets            []string
	AutoEnableRules         bool
	BlockPageEnabled        bool
	BaseFeed                string
	BaseExemptPrefixes      map[string]struct{}
	ProtectedRules          map[string]struct{}
	UnmanagedListKeywords   []string
	RelevanceCacheDir       string
	RelevanceMinRefreshSecs int64
	RelevanceTTLSecs        int64
	DryRun                  bool
	ForceRefreshRelevance   bool
	StrictFeeds             bool
	Raw                     rawConfig
}

func (c *appConfig) isManagedList(name string) bool {
	matched := false
	for _, t := range c.ScrubTargets {
		if strings.Contains(name, t) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, kw := range c.UnmanagedListKeywords {
		if strings.Contains(name, kw) {
			return false
		}
	}
	return true
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

func parseTimeoutSecs(v any) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case []any:
		if len(val) > 0 {
			switch last := val[len(val)-1].(type) {
			case int64:
				return last
			case float64:
				return int64(last)
			}
		}
	}
	return 30
}

func loadConfig(configPath string, dryRun, forceRefresh, strict bool) (*appConfig, error) {
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
	addExcluded := func(email string) {
		email = strings.TrimSpace(email)
		if email != "" && !slices.Contains(excluded, email) {
			excluded = append(excluded, email)
		}
	}
	addExcluded(os.Getenv("SECONDARY_EMAIL"))
	addExcluded(os.Getenv("TERTIARY_EMAIL"))
	if extra := os.Getenv("EXCLUDED_EMAILS"); extra != "" {
		for _, e := range strings.Split(extra, ",") {
			addExcluded(e)
		}
	}

	targetIdentity := ""
	if len(excluded) > 0 {
		quoted := make([]string, len(excluded))
		for i, e := range excluded {
			quoted[i] = fmt.Sprintf(`"%s"`, e)
		}
		targetIdentity = fmt.Sprintf("not(identity.email in {%s})", strings.Join(quoted, " "))
	}

	s := raw.Settings
	maxWorkers := 8
	if s.MaxWorkers != nil && *s.MaxWorkers > 0 {
		maxWorkers = *s.MaxWorkers
	}
	maxListSize := 1000
	if s.MaxListSize != nil && *s.MaxListSize > 0 {
		maxListSize = *s.MaxListSize
	}
	totalQuota := maxSafeDomains
	if s.TotalQuota != nil && *s.TotalQuota > 0 {
		totalQuota = min(*s.TotalQuota, maxSafeDomains)
	}
	timeoutSecs := max(parseTimeoutSecs(s.RequestTimeout), 5)

	autoEnable := true
	if s.AutoEnableRules != nil {
		autoEnable = *s.AutoEnableRules
	}
	blockPage := false
	if s.BlockPageEnabled != nil {
		blockPage = *s.BlockPageEnabled
	}

	baseFeed := s.BaseFeed
	if baseFeed == "" {
		baseFeed = "HaGeZi Normal"
	}

	exemptList := s.BaseExemptPrefixes
	if len(exemptList) == 0 {
		exemptList = []string{"L_Normal", "L_Relaxed"}
	}
	baseExempt := make(map[string]struct{}, len(exemptList))
	for _, p := range exemptList {
		baseExempt[p] = struct{}{}
	}

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

	unmanagedKeywords := s.UnmanagedListKeywords
	if len(unmanagedKeywords) == 0 {
		unmanagedKeywords = []string{"IoT Bypass"}
	}

	cacheDir := strings.TrimSpace(os.Getenv("RELEVANCE_CACHE_DIR"))
	if cacheDir == "" {
		cacheDir = strings.TrimSpace(s.RelevanceCacheDir)
	}
	if cacheDir == "" {
		cacheDir = filepath.Join(".cache", "relevance")
	}

	minRefreshHours := int64(24)
	if s.RelevanceMinRefreshHours != nil && *s.RelevanceMinRefreshHours >= 0 {
		minRefreshHours = *s.RelevanceMinRefreshHours
	}
	ttlDays := int64(7)
	if s.RelevanceTTLDays != nil && *s.RelevanceTTLDays >= 1 {
		ttlDays = *s.RelevanceTTLDays
	}

	if dryRun {
		logInfo("Running in --dry-run mode: no Cloudflare resources will be modified.")
	}

	return &appConfig{
		APIToken:                apiToken,
		AccountID:               accountID,
		TargetIdentity:          targetIdentity,
		MaxWorkers:              maxWorkers,
		MaxListSize:             maxListSize,
		TotalQuota:              totalQuota,
		Timeout:                 time.Duration(timeoutSecs) * time.Second,
		ScrubTargets:            s.ScrubTargets,
		AutoEnableRules:         autoEnable,
		BlockPageEnabled:        blockPage,
		BaseFeed:                baseFeed,
		BaseExemptPrefixes:      baseExempt,
		ProtectedRules:          protected,
		UnmanagedListKeywords:   unmanagedKeywords,
		RelevanceCacheDir:       cacheDir,
		RelevanceMinRefreshSecs: minRefreshHours * 3600,
		RelevanceTTLSecs:        ttlDays * 86400,
		DryRun:                  dryRun,
		ForceRefreshRelevance:   forceRefresh,
		StrictFeeds:             strict,
		Raw:                     raw,
	}, nil
}

// ---------- Cloudflare Models & API Client ----------

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

func (r gatewayRule) clone() gatewayRule {
	cp := r
	cp.Filters = slices.Clone(r.Filters)
	if r.RuleSettings != nil {
		cp.RuleSettings = make(map[string]any, len(r.RuleSettings))
		for k, v := range r.RuleSettings {
			cp.RuleSettings[k] = v
		}
	}
	return cp
}

type cfEnvelope struct {
	Success    *bool           `json:"success"`
	Result     json.RawMessage `json:"result"`
	Errors     json.RawMessage `json:"errors"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func isNonNullRaw(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func newHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

type cloudflareAPI struct {
	client      *http.Client
	baseURL     string
	token       string
	dryRun      bool
	mu          sync.Mutex
	nextWriteAt time.Time
}

func newCloudflareAPI(cfg *appConfig) *cloudflareAPI {
	return &cloudflareAPI{
		client:      newHTTPClient(cfg.Timeout),
		baseURL:     fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/gateway", cfg.AccountID),
		token:       cfg.APIToken,
		dryRun:      cfg.DryRun,
		nextWriteAt: time.Now(),
	}
}

func (cf *cloudflareAPI) paceWrite(ctx context.Context) error {
	cf.mu.Lock()
	now := time.Now()
	target := cf.nextWriteAt
	if now.After(target) {
		target = now
	}
	cf.nextWriteAt = target.Add(220*time.Millisecond + jitterMs(60))
	cf.mu.Unlock()

	if wait := time.Until(target); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (cf *cloudflareAPI) backoffAllWriters(wait time.Duration) {
	cf.mu.Lock()
	resume := time.Now().Add(wait)
	if resume.After(cf.nextWriteAt) {
		cf.nextWriteAt = resume
	}
	cf.mu.Unlock()
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isTransientStatus(code int) bool {
	return code == 408 || (code >= 500 && code <= 504) || (code >= 520 && code <= 530)
}

func (cf *cloudflareAPI) req(ctx context.Context, method, endpoint string, body any) (*cfEnvelope, error) {
	url := cf.baseURL + "/" + endpoint
	const retries = 6
	const baseDelaySecs = 2

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body for %s %s: %w", method, endpoint, err)
		}
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
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < retries-1 {
				wait := time.Duration(min(baseDelaySecs*(1<<attempt), 60))*time.Second + jitterMs(1000)
				logWarn("Network error on %s %s: %v. Retrying in %.2fs...", method, endpoint, err, wait.Seconds())
				if err := sleepWithContext(ctx, wait); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}

		respBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			if attempt < retries-1 {
				wait := time.Duration(min(baseDelaySecs*(1<<attempt), 60))*time.Second + jitterMs(1000)
				logWarn("Body read error on %s %s: %v. Retrying in %.2fs...", method, endpoint, readErr, wait.Seconds())
				if err := sleepWithContext(ctx, wait); err != nil {
					return nil, err
				}
				continue
			}
			return nil, readErr
		}

		code := resp.StatusCode
		if code == http.StatusTooManyRequests && attempt < retries-1 {
			waitSecs := baseDelaySecs * (1 << attempt)
			if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
				if parsed, err := strconv.Atoi(ra); err == nil {
					waitSecs = parsed
				}
			}
			waitSecs = min(max(waitSecs, 1), 120)
			wait := time.Duration(waitSecs)*time.Second + jitterMs(1000)
			cf.backoffAllWriters(wait)
			logWarn("Rate limited (429) on %s %s. Backing off all writers for %.2fs.", method, endpoint, wait.Seconds())
			if err := sleepWithContext(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}

		if isTransientStatus(code) && attempt < retries-1 {
			wait := time.Duration(min(baseDelaySecs*(1<<attempt), 60))*time.Second + jitterMs(1000)
			logWarn("Transient HTTP %d on %s %s. Retrying in %.2fs...", code, method, endpoint, wait.Seconds())
			if err := sleepWithContext(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}

		if code < 200 || code >= 300 {
			text := string(respBytes)
			logErr("Cloudflare API error [%d] on %s %s: %s", code, method, endpoint, text)
			return nil, fmt.Errorf("HTTP %d on %s %s: %s", code, method, endpoint, text)
		}

		var env cfEnvelope
		if err := json.Unmarshal(respBytes, &env); err != nil {
			snippet := string(respBytes)
			if len(snippet) > 300 {
				snippet = snippet[:300]
			}
			return nil, fmt.Errorf("invalid JSON from %s %s: %w (%s)", method, endpoint, err, snippet)
		}
		if env.Success != nil && !*env.Success {
			logErr("Cloudflare API error payload on %s %s: %s", method, endpoint, string(env.Errors))
			return nil, fmt.Errorf("Cloudflare API failed on %s: %s", endpoint, string(env.Errors))
		}
		return &env, nil
	}

	return nil, fmt.Errorf("exceeded max retries on Cloudflare endpoint: %s", endpoint)
}

func paginate[T any](cf *cloudflareAPI, endpoint string) ([]T, error) {
	var results []T
	for page := 1; ; page++ {
		env, err := cf.req(context.Background(), http.MethodGet, fmt.Sprintf("%s?page=%d&per_page=100", endpoint, page), nil)
		if err != nil {
			return nil, err
		}
		if isNonNullRaw(env.Result) {
			var pageItems []T
			if err := json.Unmarshal(env.Result, &pageItems); err != nil {
				return nil, fmt.Errorf("failed to deserialize %s page %d: %w", endpoint, page, err)
			}
			results = append(results, pageItems...)
		}
		totalPages := env.ResultInfo.TotalPages
		if totalPages < 1 {
			totalPages = 1
		}
		if page >= totalPages {
			break
		}
	}
	return results, nil
}

func (cf *cloudflareAPI) getLists() ([]gatewayList, error) { return paginate[gatewayList](cf, "lists") }
func (cf *cloudflareAPI) getRules() ([]gatewayRule, error) { return paginate[gatewayRule](cf, "rules") }

func (cf *cloudflareAPI) deleteList(lid string) error {
	if cf.dryRun {
		logInfo("[DRY-RUN] Would DELETE lists/%s", lid)
		return nil
	}
	_, err := cf.req(context.Background(), http.MethodDelete, "lists/"+lid, nil)
	return err
}

func (cf *cloudflareAPI) deleteRule(rid string) error {
	if cf.dryRun {
		logInfo("[DRY-RUN] Would DELETE rules/%s", rid)
		return nil
	}
	_, err := cf.req(context.Background(), http.MethodDelete, "rules/"+rid, nil)
	return err
}

type listItemPayload struct {
	Value string `json:"value"`
}

func (cf *cloudflareAPI) createList(ctx context.Context, name string, items []string, listType, desc string) (string, error) {
	if cf.dryRun {
		logInfo("[DRY-RUN] Would CREATE list '%s' (%d %s items)", name, len(items), listType)
		return "dry-run-" + strings.ReplaceAll(name, " ", "-"), nil
	}
	wrapped := make([]listItemPayload, len(items))
	for i, v := range items {
		wrapped[i] = listItemPayload{Value: v}
	}
	payload := map[string]any{
		"name":        name,
		"type":        listType,
		"items":       wrapped,
		"description": desc,
	}
	env, err := cf.req(ctx, http.MethodPost, "lists", payload)
	if err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(env.Result, &created); err != nil || created.ID == "" {
		return "", fmt.Errorf("Cloudflare createList response missing result.id for '%s'", name)
	}
	return created.ID, nil
}

func (cf *cloudflareAPI) updateList(ctx context.Context, lid, name string, items []string, desc string) error {
	if cf.dryRun {
		logInfo("[DRY-RUN] Would UPDATE list '%s' (%s, %d items)", name, lid, len(items))
		return nil
	}
	wrapped := make([]listItemPayload, len(items))
	for i, v := range items {
		wrapped[i] = listItemPayload{Value: v}
	}
	payload := map[string]any{
		"name":        name,
		"items":       wrapped,
		"description": desc,
	}
	_, err := cf.req(ctx, http.MethodPut, "lists/"+lid, payload)
	return err
}

func ensureRuleSettings(payload map[string]any) {
	settings, ok := payload["rule_settings"].(map[string]any)
	if !ok || settings == nil {
		settings = map[string]any{}
		payload["rule_settings"] = settings
	}
	if _, exists := settings["block_page_enabled"]; !exists {
		settings["block_page_enabled"] = false
	}
}

func (cf *cloudflareAPI) createRule(payload map[string]any) (*gatewayRule, error) {
	ensureRuleSettings(payload)
	if cf.dryRun {
		logInfo("[DRY-RUN] Would CREATE rule '%v'", payload["name"])
		return nil, nil
	}
	env, err := cf.req(context.Background(), http.MethodPost, "rules", payload)
	if err != nil {
		return nil, err
	}
	if !isNonNullRaw(env.Result) {
		return nil, nil
	}
	var created gatewayRule
	if err := json.Unmarshal(env.Result, &created); err != nil {
		return nil, fmt.Errorf("deserialize created rule: %w", err)
	}
	return &created, nil
}

func (cf *cloudflareAPI) updateRule(rid string, payload map[string]any) (*gatewayRule, error) {
	ensureRuleSettings(payload)
	if cf.dryRun {
		logInfo("[DRY-RUN] Would UPDATE rule '%v' (%s)", payload["name"], rid)
		return nil, nil
	}
	env, err := cf.req(context.Background(), http.MethodPut, "rules/"+rid, payload)
	if err != nil {
		return nil, err
	}
	if !isNonNullRaw(env.Result) {
		return nil, nil
	}
	var updated gatewayRule
	if err := json.Unmarshal(env.Result, &updated); err != nil {
		return nil, fmt.Errorf("deserialize updated rule: %w", err)
	}
	return &updated, nil
}

// ---------- Domain & IP Validation ----------

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isValidASCIILabel(label string) bool {
	n := len(label)
	if n == 0 || n > 63 || label[0] == '-' || label[n-1] == '-' {
		return false
	}
	for i := 0; i < n; i++ {
		c := label[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func isValidTLD(tld string) bool {
	n := len(tld)
	if n < 2 || n > 63 {
		return false
	}
	allAlpha := true
	for i := 0; i < n; i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			allAlpha = false
			break
		}
	}
	if allAlpha {
		return true
	}
	return strings.HasPrefix(tld, "xn--") && n >= 5 && isValidASCIILabel(tld)
}

func isFastASCIIDomain(s string) bool {
	if len(s) > 253 || strings.Contains(s, "--") {
		return false
	}
	labels := 0
	last := ""
	rest := s
	for {
		dot := strings.IndexByte(rest, '.')
		var lbl string
		if dot < 0 {
			lbl = rest
		} else {
			lbl = rest[:dot]
		}
		if !isValidASCIILabel(lbl) {
			return false
		}
		labels++
		last = lbl
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	if labels < 2 || len(last) < 2 {
		return false
	}
	for i := 0; i < len(last); i++ {
		if last[i] < 'a' || last[i] > 'z' {
			return false
		}
	}
	return true
}

func normalizeDomain(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if strings.ContainsAny(s, "/?:*") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		if idx := strings.IndexByte(s, '?'); idx >= 0 {
			s = s[:idx]
		}
		if idx := strings.IndexByte(s, '/'); idx >= 0 {
			s = s[:idx]
		}
		if idx := strings.IndexByte(s, ':'); idx >= 0 {
			s = s[:idx]
		}
		s = strings.TrimPrefix(s, "*.")
		s = strings.Trim(s, ".")
	}
	if s == "" || len(s) > 253 || !strings.ContainsRune(s, '.') || strings.Contains(s, "..") {
		return "", false
	}

	if isFastASCIIDomain(s) {
		return s, true
	}

	var d string
	if isASCII(s) {
		d = strings.ToLower(s)
	} else {
		var err error
		d, err = idna.Lookup.ToASCII(strings.ToLower(s))
		if err != nil {
			return "", false
		}
	}

	if len(d) > 253 {
		return "", false
	}
	if isFastASCIIDomain(d) {
		return d, true
	}

	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, lbl := range labels {
		if !isValidASCIILabel(lbl) {
			return "", false
		}
		if len(lbl) >= 4 && lbl[2] == '-' && lbl[3] == '-' {
			if !strings.HasPrefix(lbl, "xn--") {
				return "", false
			}
			if _, err := idna.Lookup.ToUnicode(lbl); err != nil {
				return "", false
			}
		}
	}
	if !isValidTLD(labels[len(labels)-1]) {
		return "", false
	}
	return d, true
}

func hasParentDomain(host string, lookup map[string]struct{}) bool {
	rest := host
	for {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return false
		}
		parent := rest[dot+1:]
		if !strings.ContainsRune(parent, '.') {
			return false
		}
		if _, ok := lookup[parent]; ok {
			return true
		}
		rest = parent
	}
}

func hasSuffixDomain(host string, lookup map[string]struct{}) bool {
	if _, ok := lookup[host]; ok {
		return true
	}
	return hasParentDomain(host, lookup)
}

func isNonRoutableIP(p netip.Prefix) bool {
	p = p.Masked()
	addr := p.Addr()
	if addr.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
		addr = p.Addr()
	}
	if addr.Is4() {
		for _, r := range reservedV4Nets {
			if r.Overlaps(p) {
				return true
			}
		}
		return false
	}
	for _, r := range reservedV6Nets {
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}

// ---------- Flat Sorted Relevance Set & Binary Cache ----------

type relevanceSet struct {
	hashes []uint64 // sorted, deduplicated; zero GC pointer overhead
}

func (rs *relevanceSet) len() int {
	if rs == nil {
		return 0
	}
	return len(rs.hashes)
}

func (rs *relevanceSet) contains(h uint64) bool {
	_, ok := slices.BinarySearch(rs.hashes, h)
	return ok
}

func (rs *relevanceSet) matches(host string) bool {
	if rs.contains(xxh3.HashString(host)) {
		return true
	}
	rest := host
	for {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return false
		}
		parent := rest[dot+1:]
		if !strings.ContainsRune(parent, '.') {
			return false
		}
		if rs.contains(xxh3.HashString(parent)) {
			return true
		}
		rest = parent
	}
}

type relevanceMeta struct {
	Version       int               `json:"version"`
	CreatedAt     int64             `json:"created_at"`
	DomainCount   int               `json:"domain_count"`
	SourceHeaders map[string]string `json:"source_headers"`
}

func atomicRename(tmp, dest string) error {
	if err := os.Rename(tmp, dest); err != nil {
		if runtime.GOOS == "windows" {
			_ = os.Remove(dest)
			return os.Rename(tmp, dest)
		}
		return err
	}
	return nil
}

func extractHeaderFingerprint(h http.Header) string {
	etag := strings.TrimSpace(h.Get("ETag"))
	lm := strings.TrimSpace(h.Get("Last-Modified"))
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
		go func(spec topListSpec) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, spec.URL, nil)
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
					out[spec.URL] = fp
					mu.Unlock()
				}
			}
		}(spec)
	}
	wg.Wait()
	return out
}

func saveRelevanceCache(cacheDir string, rs *relevanceSet, meta *relevanceMeta) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	binPath := filepath.Join(cacheDir, "relevance.bin")
	binTmp := filepath.Join(cacheDir, "relevance.bin.tmp")
	metaPath := filepath.Join(cacheDir, "relevance.meta.json")
	metaTmp := filepath.Join(cacheDir, "relevance.meta.json.tmp")

	f, err := os.Create(binTmp)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 256*1024)
	hasher := xxh3.New()

	var hdr [16]byte
	copy(hdr[:8], cacheMagicV2)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(len(rs.hashes)))
	if _, err := bw.Write(hdr[:]); err != nil {
		f.Close()
		return err
	}

	chunkBuf := make([]byte, 8192*8)
	for i := 0; i < len(rs.hashes); i += 8192 {
		end := min(i+8192, len(rs.hashes))
		nBytes := (end - i) * 8
		for j, h := range rs.hashes[i:end] {
			binary.LittleEndian.PutUint64(chunkBuf[j*8:(j+1)*8], h)
		}
		_, _ = hasher.Write(chunkBuf[:nBytes])
		if _, err := bw.Write(chunkBuf[:nBytes]); err != nil {
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
	binPath := filepath.Join(cacheDir, "relevance.bin")
	f, err := os.Open(binPath)
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
	magic := string(hdr[:8])
	if magic != cacheMagicV2 && magic != cacheMagicV1 {
		return nil, fmt.Errorf("invalid relevance cache magic header: %q", magic)
	}

	count := binary.LittleEndian.Uint64(hdr[8:16])
	if count < minRelevanceDomains {
		return nil, fmt.Errorf("relevance cache count (%d) below minimum threshold", count)
	}
	expectedLen := int64(count)*8 + 24
	if stat.Size() != expectedLen {
		return nil, fmt.Errorf("relevance cache truncated (expected %d bytes, got %d)", expectedLen, stat.Size())
	}

	hashes := make([]uint64, count)
	hasher := xxh3.New()
	chunkBuf := make([]byte, 8192*8)
	sorted := true
	var prev uint64

	for i := 0; i < int(count); i += 8192 {
		take := min(8192, int(count)-i)
		nBytes := take * 8
		if _, err := io.ReadFull(br, chunkBuf[:nBytes]); err != nil {
			return nil, err
		}
		_, _ = hasher.Write(chunkBuf[:nBytes])
		for j := 0; j < take; j++ {
			v := binary.LittleEndian.Uint64(chunkBuf[j*8 : (j+1)*8])
			if i+j > 0 && v < prev {
				sorted = false
			}
			prev = v
			hashes[i+j] = v
		}
	}

	var trailer [8]byte
	if _, err := io.ReadFull(br, trailer[:]); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint64(trailer[:]) != hasher.Sum64() {
		return nil, errors.New("relevance cache checksum mismatch (corrupted file)")
	}

	if !sorted {
		slices.Sort(hashes)
		hashes = slices.Compact(hashes)
	}
	return &relevanceSet{hashes: hashes}, nil
}

func loadRelevanceMeta(cacheDir string) *relevanceMeta {
	data, err := os.ReadFile(filepath.Join(cacheDir, "relevance.meta.json"))
	if err != nil {
		return nil
	}
	var m relevanceMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &m
}

// ---------- Feed Fetching & Parsing ----------

func fetchWithRetryMeta(client *http.Client, url string) ([]byte, string, error) {
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("User-Agent", uaStr)
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return body, extractHeaderFingerprint(resp.Header), nil
			}
			if readErr != nil {
				err = readErr
			} else {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
		if attempt < 4 {
			wait := time.Duration(1500*(1<<attempt))*time.Millisecond + jitterMs(500)
			if attempt >= 2 {
				logWarn("Fetch attempt %d/5 failed for %s: %v. Retrying...", attempt+1, url, err)
			}
			time.Sleep(wait)
		} else {
			return nil, "", err
		}
	}
	return nil, "", errors.New("unreachable")
}

func fetchWithRetry(client *http.Client, url string) ([]byte, error) {
	b, _, err := fetchWithRetryMeta(client, url)
	return b, err
}

func parseCSVStream(r io.Reader, col int, skipHeader bool) []uint64 {
	var hashes []uint64
	br := bufio.NewReaderSize(r, 64*1024)
	idx := 0
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			curIdx := idx
			idx++
			if !(skipHeader && curIdx == 0) {
				if rawCol, ok := nthCSVCol(line, col); ok {
					trimmed := strings.Trim(strings.TrimSpace(rawCol), `"`)
					if trimmed != "" {
						if clean, ok := normalizeDomain(trimmed); ok {
							hashes = append(hashes, xxh3.HashString(clean))
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	slices.Sort(hashes)
	return slices.Compact(hashes)
}

func nthCSVCol(line string, col int) (string, bool) {
	cur := 0
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == ',' {
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
	return "", false
}

func buildFreshRelevanceDataset(client *http.Client) (*relevanceSet, map[string]string, error) {
	logInfo("Fetching fresh relevance datasets directly from sources...")
	type itemResult struct {
		url    string
		fp     string
		hashes []uint64
	}
	results := make([]itemResult, len(defaultTopLists))
	var wg sync.WaitGroup

	for i, spec := range defaultTopLists {
		wg.Add(1)
		go func(i int, spec topListSpec) {
			defer wg.Done()
			rawBytes, fp, err := fetchWithRetryMeta(client, spec.URL)
			if err != nil {
				logWarn("Failed to fetch top list (%s): %v", spec.URL, err)
				results[i] = itemResult{url: spec.URL}
				return
			}

			var parsed []uint64
			switch spec.Compression {
			case "zip":
				zr, err := zip.NewReader(bytes.NewReader(rawBytes), int64(len(rawBytes)))
				if err != nil {
					logWarn("Failed opening zip archive from %s: %v", spec.URL, err)
					results[i] = itemResult{url: spec.URL, fp: fp}
					return
				}
				var target *zip.File
				for _, f := range zr.File {
					lower := strings.ToLower(f.Name)
					if (strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".txt")) && !strings.HasSuffix(lower, "/") {
						target = f
						break
					}
				}
				if target == nil && len(zr.File) > 0 {
					target = zr.File[0]
				}
				if target != nil {
					if rc, err := target.Open(); err == nil {
						parsed = parseCSVStream(rc, spec.Col, spec.SkipHeader)
						rc.Close()
					}
				}
			case "gzip":
				if gz, err := gzip.NewReader(bytes.NewReader(rawBytes)); err == nil {
					parsed = parseCSVStream(gz, spec.Col, spec.SkipHeader)
					gz.Close()
				}
			default:
				parsed = parseCSVStream(bytes.NewReader(rawBytes), spec.Col, spec.SkipHeader)
			}

			logInfo("Fetched & parsed %d domains from %s", len(parsed), spec.URL)
			results[i] = itemResult{url: spec.URL, fp: fp, hashes: parsed}
		}(i, spec)
	}
	wg.Wait()

	headersMap := make(map[string]string, len(results))
	totalCap := 0
	for _, r := range results {
		if r.fp != "" {
			headersMap[r.url] = r.fp
		}
		totalCap += len(r.hashes)
	}

	master := make([]uint64, 0, totalCap)
	for i := range results {
		master = append(master, results[i].hashes...)
		results[i].hashes = nil
	}
	slices.Sort(master)
	master = slices.Compact(master)
	master = slices.Clip(master)

	if len(master) < minRelevanceDomains {
		return nil, nil, fmt.Errorf("relevance dataset critically low (%d domains)", len(master))
	}
	logInfo("Relevance dataset compiled: %d hashed root domains.", len(master))
	return &relevanceSet{hashes: master}, headersMap, nil
}

func resolveRelevanceDataset(client *http.Client, cfg *appConfig) (*relevanceSet, string, error) {
	binPath := filepath.Join(cfg.RelevanceCacheDir, "relevance.bin")
	_, statErr := os.Stat(binPath)
	binExists := statErr == nil
	var cachedMeta *relevanceMeta
	if binExists {
		cachedMeta = loadRelevanceMeta(cfg.RelevanceCacheDir)
	}
	now := time.Now().Unix()

	if !cfg.ForceRefreshRelevance && cachedMeta != nil {
		ageSecs := max(now-cachedMeta.CreatedAt, 0)
		shouldUseCache := false

		if ageSecs < cfg.RelevanceMinRefreshSecs {
			logInfo("Relevance cache is %.1fh old (under %dh min refresh); loading directly from disk.",
				float64(ageSecs)/3600.0, cfg.RelevanceMinRefreshSecs/3600)
			shouldUseCache = true
		} else if ageSecs < cfg.RelevanceTTLSecs {
			logInfo("Relevance cache is %.1fd old; checking upstream HEAD headers for changes...",
				float64(ageSecs)/86400.0)
			probes := probeTopListHeaders(client)
			changedURL := ""
			for url, newFP := range probes {
				if oldFP, ok := cachedMeta.SourceHeaders[url]; ok && newFP != oldFP {
					changedURL = url
					break
				}
			}
			if changedURL != "" {
				logInfo("Upstream top-list header changed (%s); refreshing relevance cache.", changedURL)
			} else {
				logInfo("No upstream top-list changes detected; reusing cached relevance dataset.")
				shouldUseCache = true
			}
		} else {
			logInfo("Relevance cache expired (%.1fd >= %dd TTL); refreshing dataset.",
				float64(ageSecs)/86400.0, cfg.RelevanceTTLSecs/86400)
		}

		if shouldUseCache {
			rs, err := loadRelevanceCache(cfg.RelevanceCacheDir)
			if err == nil {
				logInfo("Loaded %d hashed root domains from relevance cache.", rs.len())
				return rs, "cache-hit", nil
			}
			logWarn("Cached relevance.bin unusable (%v); rebuilding from upstream.", err)
		}
	}

	rs, sourceHeaders, err := buildFreshRelevanceDataset(client)
	if err == nil {
		meta := &relevanceMeta{
			Version:       2,
			CreatedAt:     now,
			DomainCount:   rs.len(),
			SourceHeaders: sourceHeaders,
		}
		if saveErr := saveRelevanceCache(cfg.RelevanceCacheDir, rs, meta); saveErr != nil {
			logWarn("Failed writing relevance cache to %s: %v (continuing sync)", cfg.RelevanceCacheDir, saveErr)
		} else {
			logInfo("Saved relevance cache to %s (%d hashes).", cfg.RelevanceCacheDir, rs.len())
		}
		return rs, "refreshed", nil
	}

	if binExists {
		logWarn("Fresh relevance fetch failed (%v). Attempting fallback to existing stale cache...", err)
		if stale, loadErr := loadRelevanceCache(cfg.RelevanceCacheDir); loadErr == nil {
			logWarn("Self-healed using stale relevance cache (%d hashes) to keep sync running.", stale.len())
			return stale, "stale-fallback", nil
		}
	}
	return nil, "", fmt.Errorf("relevance dataset unavailable and no valid local cache exists: %w", err)
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
		raw := table[name]
		switch val := raw.(type) {
		case string:
			out = append(out, sourceSpec{Name: name, URLs: []string{val}, EnableRelevance: !isIP})
		case []any:
			var urls []string
			for _, u := range val {
				if s, ok := u.(string); ok {
					urls = append(urls, s)
				}
			}
			out = append(out, sourceSpec{Name: name, URLs: urls, EnableRelevance: !isIP})
		case map[string]any:
			var urls []string
			if arr, ok := val["urls"].([]any); ok {
				for _, u := range arr {
					if s, ok := u.(string); ok {
						urls = append(urls, s)
					}
				}
			} else if u, ok := val["url"].(string); ok {
				urls = []string{u}
			}
			enableRel := !isIP
			if !isIP {
				if rel, ok := val["relevance"].(bool); ok {
					enableRel = rel
				}
			}
			out = append(out, sourceSpec{Name: name, URLs: urls, EnableRelevance: enableRel})
		}
	}
	return out
}

func ingestDomainToken(rawTok string, rel *relevanceSet, kept map[string]struct{}) {
	beforeMod := rawTok
	if idx := strings.IndexByte(rawTok, '$'); idx >= 0 {
		beforeMod = rawTok[:idx]
		mods := rawTok[idx+1:]
		for _, opt := range strings.Split(mods, ",") {
			if strings.EqualFold(opt, "badfilter") {
				return
			}
		}
	}
	token := strings.TrimPrefix(beforeMod, "||")
	if idx := strings.IndexByte(token, '^'); idx >= 0 {
		token = token[:idx]
	}
	clean, ok := normalizeDomain(token)
	if !ok {
		return
	}
	if _, exists := kept[clean]; exists {
		return
	}
	if rel != nil {
		checkDom := strings.TrimPrefix(clean, "www.")
		if !rel.matches(checkDom) {
			return
		}
	}
	kept[clean] = struct{}{}
}

func fetchFeedSource(client *http.Client, spec sourceSpec, rel *relevanceSet) (map[string]struct{}, error) {
	kept := make(map[string]struct{})
	for _, u := range spec.URLs {
		rawBytes, err := fetchWithRetry(client, u)
		if err != nil {
			return nil, err
		}
		br := bufio.NewReaderSize(bytes.NewReader(rawBytes), 64*1024)
		for {
			line, readErr := br.ReadString('\n')
			if len(line) > 0 {
				line = strings.TrimSpace(line)
				if line != "" &&
					line[0] != '#' && line[0] != '!' && line[0] != '/' &&
					!strings.HasPrefix(line, "@@") &&
					!strings.Contains(line, "##") &&
					!strings.Contains(line, "#@#") &&
					!strings.Contains(line, "#?#") &&
					!strings.Contains(line, "#$#") {

					if idx := strings.IndexAny(line, "#!;"); idx >= 0 {
						line = strings.TrimSpace(line[:idx])
					}
					if line != "" {
						fields := strings.Fields(line)
						if len(fields) > 0 {
							if _, ipErr := netip.ParseAddr(fields[0]); ipErr == nil {
								for _, tok := range fields[1:] {
									ingestDomainToken(tok, rel, kept)
								}
							} else {
								ingestDomainToken(fields[len(fields)-1], rel, kept)
							}
						}
					}
				}
			}
			if readErr != nil {
				break
			}
		}
	}
	logInfo("Fetched %s: %d kept", spec.Name, len(kept))
	return kept, nil
}

func fetchIPSource(client *http.Client, spec sourceSpec) (map[netip.Prefix]struct{}, error) {
	networks := make(map[netip.Prefix]struct{})
	replacer := strings.NewReplacer(`"`, " ", `'`, " ", ",", " ", "\t", " ")

	for _, u := range spec.URLs {
		rawBytes, err := fetchWithRetry(client, u)
		if err != nil {
			return nil, err
		}
		br := bufio.NewReaderSize(bytes.NewReader(rawBytes), 64*1024)
		for {
			line, readErr := br.ReadString('\n')
			if len(line) > 0 {
				line = strings.TrimSpace(line)
				if line != "" && line[0] != '#' && line[0] != ';' && line[0] != '/' {
					for _, sep := range []string{"#", ";", "//"} {
						if idx := strings.Index(line, sep); idx >= 0 {
							line = line[:idx]
						}
					}
					line = strings.TrimSpace(line)
					if line != "" {
						for _, rawTok := range strings.Fields(replacer.Replace(line)) {
							tok := strings.Trim(rawTok, "[]")
							if !strings.ContainsAny(tok, ".:") {
								continue
							}
							if strings.ContainsRune(tok, '.') && strings.Count(tok, ":") == 1 {
								tok, _, _ = strings.Cut(tok, ":")
							} else if v6Part, _, found := strings.Cut(rawTok, "]:"); found {
								tok = strings.TrimPrefix(v6Part, "[")
							}

							var prefix netip.Prefix
							var parseErr error
							if strings.ContainsRune(tok, '/') {
								prefix, parseErr = netip.ParsePrefix(tok)
								if parseErr == nil {
									prefix = prefix.Masked()
								}
							} else {
								var addr netip.Addr
								addr, parseErr = netip.ParseAddr(tok)
								if parseErr == nil {
									if addr.Is4In6() {
										addr = addr.Unmap()
									}
									prefix = netip.PrefixFrom(addr, addr.BitLen())
								}
							}

							if parseErr == nil && !isNonRoutableIP(prefix) {
								if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
									prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
								}
								networks[prefix] = struct{}{}
							}
						}
					}
				}
			}
			if readErr != nil {
				break
			}
		}
	}
	logInfo("Fetched IP feed %s: %d unique subnets/IPs", spec.Name, len(networks))
	return networks, nil
}

func fetchSpamTLDs(client *http.Client, url string) (string, map[string]struct{}, error) {
	rawBytes, err := fetchWithRetry(client, url)
	if err != nil {
		return "", nil, err
	}
	tldSet := make(map[string]struct{})
	br := bufio.NewReader(bytes.NewReader(rawBytes))
	for {
		line, readErr := br.ReadString('\n')
		if len(line) > 0 {
			l := strings.ToLower(strings.TrimSpace(line))
			if l != "" && l[0] != '#' && l[0] != '!' && l[0] != '/' {
				fields := strings.Fields(l)
				if len(fields) > 0 {
					clean := strings.Trim(strings.TrimPrefix(fields[len(fields)-1], "*."), ".")
					if clean != "" && !strings.ContainsAny(clean, ".*") {
						tldSet[clean] = struct{}{}
					}
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	if len(tldSet) == 0 {
		return "", nil, fmt.Errorf("zero TLDs parsed from %s", url)
	}
	sorted := make([]string, 0, len(tldSet))
	for t := range tldSet {
		sorted = append(sorted, t)
	}
	slices.Sort(sorted)
	expr := fmt.Sprintf(`any(dns.domains[*] matches "(?i)\.(%s)$")`, strings.Join(sorted, "|"))
	return expr, tldSet, nil
}

// ---------- Policy Compilation ----------

type fetchedFeed struct {
	IsIP    bool
	Domains map[string]struct{}
	IPs     map[netip.Prefix]struct{}
}

type compiledPolicy struct {
	Policy  policyConfig
	Entries []string
}

func buildPolicySets(
	cfg *appConfig,
	policies []policyConfig,
	fetched map[string]fetchedFeed,
	spamTLDs map[string]struct{},
	hasActiveSpamTLD bool,
) []compiledPolicy {
	var baseSet map[string]struct{}
	if feed, ok := fetched[cfg.BaseFeed]; ok && !feed.IsIP {
		baseSet = feed.Domains
	}

	out := make([]compiledPolicy, len(policies))
	sem := make(chan struct{}, cfg.MaxWorkers)
	var wg sync.WaitGroup

	for i, pol := range policies {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p policyConfig) {
			defer wg.Done()
			defer func() { <-sem }()

			if p.resolvedType() == "IP" {
				var builder netipx.IPSetBuilder
				for _, inc := range p.Include {
					if feed, ok := fetched[inc]; ok && feed.IsIP {
						for pf := range feed.IPs {
							builder.AddPrefix(pf)
						}
					}
				}
				for _, exc := range p.Exclude {
					if feed, ok := fetched[exc]; ok && feed.IsIP {
						for pf := range feed.IPs {
							builder.RemovePrefix(pf)
						}
					}
				}
				var collapsed []string
				if ipSet, err := builder.IPSet(); err == nil && ipSet != nil {
					prefixes := ipSet.Prefixes()
					collapsed = make([]string, len(prefixes))
					for j, pf := range prefixes {
						collapsed[j] = pf.String()
					}
				}
				out[i] = compiledPolicy{Policy: p.clone(), Entries: collapsed}
				return
			}

			pSet := make(map[string]struct{})
			for _, inc := range p.Include {
				if feed, ok := fetched[inc]; ok && !feed.IsIP {
					for d := range feed.Domains {
						pSet[d] = struct{}{}
					}
				}
			}
			for _, exc := range p.Exclude {
				if feed, ok := fetched[exc]; ok && !feed.IsIP {
					for d := range feed.Domains {
						delete(pSet, d)
					}
				}
			}

			if p.resolvedAction() != "allow" {
				if baseSet != nil {
					_, exempt := cfg.BaseExemptPrefixes[p.Prefix]
					if !exempt && !slices.Contains(p.Include, cfg.BaseFeed) {
						for d := range pSet {
							if hasSuffixDomain(d, baseSet) {
								delete(pSet, d)
							}
						}
					}
				}
				if len(spamTLDs) > 0 && (p.UseSpamTLD || hasActiveSpamTLD) {
					for d := range pSet {
						if dot := strings.LastIndexByte(d, '.'); dot >= 0 {
							if _, blocked := spamTLDs[d[dot+1:]]; blocked {
								delete(pSet, d)
							}
						}
					}
				}
			}

			pruned := make([]string, 0, len(pSet))
			for d := range pSet {
				if !hasParentDomain(d, pSet) {
					pruned = append(pruned, d)
				}
			}
			slices.Sort(pruned)
			out[i] = compiledPolicy{Policy: p.clone(), Entries: pruned}
		}(i, pol)
	}
	wg.Wait()
	return out
}

func compileCategoryExpression(p policyConfig) string {
	var parts []string
	catSpecs := []struct {
		vals  []any
		field string
	}{
		{p.SecurityCategories, "dns.security_category[*]"},
		{p.ContentCategories, "dns.content_category[*]"},
		{p.AppIDs, "app.ids[*]"},
	}
	for _, spec := range catSpecs {
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

// ---------- Prefix, Clause, & Rule Helpers ----------

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
	if err != nil {
		return 0, false
	}
	return n, true
}

func chunkMatchesRemote(target gatewayList, expectedName, rawHash string, rawLen int) bool {
	if target.Name != expectedName {
		return false
	}
	if storedHash, storedLen, hasSep := strings.Cut(target.Description, ":"); hasSep {
		if storedHash == rawHash {
			if expectedCount, err := strconv.ParseInt(storedLen, 10, 64); err == nil {
				return target.Count == nil || *target.Count == expectedCount
			}
		}
	}
	return target.Description == rawHash && (target.Count == nil || int(*target.Count) == rawLen)
}

func clauseReferencesID(clause, id string) bool {
	if id == "" {
		return false
	}
	needle := "$" + id
	start := 0
	for {
		pos := strings.Index(clause[start:], needle)
		if pos < 0 {
			return false
		}
		end := start + pos + len(needle)
		if end >= len(clause) {
			return true
		}
		c := clause[end]
		isIdent := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !isIdent {
			return true
		}
		start = end
	}
}

func stripListsFromTraffic(traffic string, listIDs []string) (string, bool) {
	clauses := strings.Split(traffic, " or ")
	kept := make([]string, 0, len(clauses))
	for _, cl := range clauses {
		referenced := false
		for _, id := range listIDs {
			if clauseReferencesID(cl, id) {
				referenced = true
				break
			}
		}
		if !referenced {
			kept = append(kept, cl)
		}
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, " or "), true
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
		"name":    rule.Name,
		"action":  action,
		"enabled": enabled,
		"filters": filters,
		"traffic": traffic,
	}
	if rule.Identity != "" {
		payload["identity"] = rule.Identity
	}
	if isNonNullRaw(rule.DevicePosture) {
		payload["device_posture"] = rule.DevicePosture
	}
	if rule.RuleSettings != nil {
		cp := make(map[string]any, len(rule.RuleSettings))
		for k, v := range rule.RuleSettings {
			cp[k] = v
		}
		payload["rule_settings"] = cp
	}
	if isNonNullRaw(rule.Schedule) {
		payload["schedule"] = rule.Schedule
	}
	if isNonNullRaw(rule.Precedence) {
		payload["precedence"] = rule.Precedence
	}
	if isNonNullRaw(rule.Description) {
		payload["description"] = rule.Description
	}
	return payload
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
		matched := false
		for _, id := range listIDs {
			if clauseReferencesID(rule.Traffic, id) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		remaining, hasRemaining := stripListsFromTraffic(rule.Traffic, listIDs)
		newTraffic := dummyTrafficExpression
		newEnabled := false
		attemptedInPlace := false
		if hasRemaining {
			newTraffic = remaining
			newEnabled = rule.Enabled
			attemptedInPlace = true
		}

		mode := "full detach (temporary disable)"
		if attemptedInPlace {
			mode = "in-place (zero-downtime)"
		}
		logInfo("Detaching stale lists from rule '%s' via %s...", rule.Name, mode)

		payload := buildRuleUpdatePayload(*rule, newEnabled, newTraffic)
		_, err := cf.updateRule(rule.ID, payload)
		if err != nil && attemptedInPlace && strings.Contains(err.Error(), "HTTP 400") {
			logWarn("In-place detach rejected with HTTP 400 for '%s'; falling back to full temporary detach.", rule.Name)
			newTraffic = dummyTrafficExpression
			newEnabled = false
			fallbackPayload := buildRuleUpdatePayload(*rule, false, dummyTrafficExpression)
			_, err = cf.updateRule(rule.ID, fallbackPayload)
		}

		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "HTTP 404") || strings.Contains(errStr, "1102") {
				logWarn("Rule '%s' (%s) no longer exists on Cloudflare; skipping detach.", rule.Name, rule.ID)
				missingIDs[rule.ID] = struct{}{}
				continue
			}
			return snapshots, fmt.Errorf("failed to detach lists from rule %s: %w", rule.Name, err)
		}

		snapshots = append(snapshots, rule.clone())
		rule.Traffic = newTraffic
		rule.Enabled = newEnabled
		detachedAny = true
	}

	if len(missingIDs) > 0 {
		filtered := rules[:0]
		for _, r := range rules {
			if _, missing := missingIDs[r.ID]; !missing {
				filtered = append(filtered, r)
			}
		}
		*existingRules = filtered
	}

	if detachedAny && !cf.dryRun {
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
			traffic, ok = stripListsFromTraffic(rule.Traffic, deletedListIDs)
			if !ok {
				logWarn("Skipping restore of '%s' because all referenced lists were already deleted.", rule.Name)
				continue
			}
		}
		payload := buildRuleUpdatePayload(rule, rule.Enabled, traffic)
		if _, err := cf.updateRule(rule.ID, payload); err != nil {
			logErr("Failed restoring rule '%s': %v", rule.Name, err)
		} else {
			logInfo("Restored rule '%s'", rule.Name)
		}
	}
}

func deleteListWithRetry(cf *cloudflareAPI, item gatewayList, existingRules *[]gatewayRule) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := cf.deleteList(item.ID)
		if err == nil {
			logInfo("Removed list: %s (%s)", item.Name, item.ID)
			return nil
		}
		errStr := err.Error()
		if strings.Contains(errStr, "HTTP 404") {
			logWarn("List %s (%s) already deleted on Cloudflare.", item.Name, item.ID)
			return nil
		}
		if strings.Contains(errStr, "HTTP 400") && strings.Contains(errStr, "in use at gateway policies") && attempt < 2 {
			_, _ = detachListsFromRules(cf, []string{item.ID}, existingRules)
			wait := time.Duration((1<<attempt)+1)*time.Second + jitterMs(500)
			logWarn("List %s still locked. Retrying in %.2fs...", item.ID, wait.Seconds())
			time.Sleep(wait)
			continue
		}
		logErr("Failed deleting list %s (%s) after %d attempts: %v", item.Name, item.ID, attempt+1, err)
		return err
	}
	return fmt.Errorf("failed deleting list %s (%s) after 3 attempts", item.Name, item.ID)
}

// ---------- Sync Operations ----------

func syncPolicyInPlace(
	cf *cloudflareAPI,
	cfg *appConfig,
	existingLists []gatewayList,
	existingRules *[]gatewayRule,
	entries []string,
	policy policyConfig,
	tldExpr string,
) ([]string, []string, []string, error) {
	if policy.Prefix == "" || policy.Name == "" {
		logWarn("Skipping malformed policy with empty prefix or name.")
		return nil, nil, nil, nil
	}

	policyType := policy.resolvedType()
	type indexedList struct {
		idx  int
		list gatewayList
	}
	var matched []indexedList
	for _, l := range existingLists {
		if idx, ok := parseChunkIndex(l.Name, policy.Prefix); ok {
			matched = append(matched, indexedList{idx: idx, list: l})
		}
	}
	slices.SortFunc(matched, func(a, b indexedList) int { return a.idx - b.idx })

	var chunks [][]string
	for i := 0; i < len(entries); i += cfg.MaxListSize {
		end := min(i+cfg.MaxListSize, len(entries))
		chunks = append(chunks, entries[i:end])
	}

	writeWorkers := min(cfg.MaxWorkers, 3)
	sem := make(chan struct{}, writeWorkers)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	chunkIDs := make([]string, len(chunks))
	var firstErr error
	var errMu sync.Mutex
	var wg sync.WaitGroup

	for idx, chunk := range chunks {
		wg.Add(1)
		go func(idx int, chunk []string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			name := fmt.Sprintf("%s %03d", policy.Prefix, idx+1)
			rawSum := sha256.Sum256([]byte(strings.Join(chunk, ",")))
			rawHash := hex.EncodeToString(rawSum[:])

			hasTarget := idx < len(matched)
			if hasTarget && chunkMatchesRemote(matched[idx].list, name, rawHash, len(chunk)) {
				chunkIDs[idx] = matched[idx].list.ID
				return
			}

			currentChunk := slices.Clone(chunk)
			for attempt := 0; attempt < maxLabelPurgeAttempts; attempt++ {
				if len(currentChunk) == 0 {
					return
				}
				desc := rawHash
				if len(currentChunk) != len(chunk) {
					desc = fmt.Sprintf("%s:%d", rawHash, len(currentChunk))
				}

				var id string
				var err error
				if hasTarget {
					id = matched[idx].list.ID
					err = cf.updateList(ctx, id, name, currentChunk, desc)
					if err == nil {
						logInfo("Updated %s (%d %s items)", name, len(currentChunk), strings.ToLower(policyType))
					}
				} else {
					id, err = cf.createList(ctx, name, currentChunk, policyType, desc)
					if err == nil {
						logInfo("Created %s (%d %s items)", name, len(currentChunk), strings.ToLower(policyType))
					}
				}

				if err == nil {
					chunkIDs[idx] = id
					return
				}

				if attempt+1 < maxLabelPurgeAttempts {
					if m := rejectedEntryRe.FindStringSubmatch(err.Error()); len(m) > 1 {
						badTok := strings.ToLower(m[1])
						before := len(currentChunk)
						filtered := currentChunk[:0]
						for _, d := range currentChunk {
							dl := strings.ToLower(d)
							if dl == badTok || slices.Contains(strings.Split(dl, "."), badTok) {
								continue
							}
							filtered = append(filtered, d)
						}
						currentChunk = filtered
						if len(currentChunk) < before {
							logWarn("Purged Cloudflare-rejected entry '%s' from %s (%d removed) and retrying...",
								badTok, name, before-len(currentChunk))
							continue
						}
					}
				}

				logErr("Error syncing %s (chunk size: %d): %v", name, len(currentChunk), err)
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				errMu.Unlock()
				return
			}
		}(idx, chunk)
	}
	wg.Wait()

	if firstErr != nil {
		return nil, nil, nil, firstErr
	}

	activeIDs := make([]string, 0, len(chunkIDs))
	for _, id := range chunkIDs {
		if id != "" {
			activeIDs = append(activeIDs, id)
		}
	}

	var surplusIDs []string
	if len(matched) > len(chunks) {
		for _, m := range matched[len(chunks):] {
			surplusIDs = append(surplusIDs, m.list.ID)
		}
	}

	var listItems []string
	if policyType == "IP" {
		for _, lid := range activeIDs {
			listItems = append(listItems, fmt.Sprintf("any(dns.resolved_ips[*] in $%s)", lid))
		}
	} else {
		for _, lid := range activeIDs {
			listItems = append(listItems, fmt.Sprintf("any(dns.domains[*] in $%s)", lid))
		}
		if tldExpr != "" && policy.UseSpamTLD {
			listItems = append(listItems, fmt.Sprintf("(%s)", tldExpr))
		}
	}
	if catExpr := compileCategoryExpression(policy); catExpr != "" {
		listItems = append(listItems, catExpr)
	}

	rules := *existingRules
	ruleIdx := slices.IndexFunc(rules, func(r gatewayRule) bool { return r.Name == policy.Name })

	if len(listItems) == 0 {
		logWarn("Policy '%s' has no active list items, categories, or expressions.", policy.Name)
		if ruleIdx >= 0 {
			rid := rules[ruleIdx].ID
			if err := cf.deleteRule(rid); err != nil {
				logErr("Failed deleting inactive rule %s: %v", policy.Name, err)
			} else {
				logInfo("Removed inactive firewall rule: %s", policy.Name)
				*existingRules = slices.Delete(rules, ruleIdx, ruleIdx+1)
			}
		}
		return activeIDs, surplusIDs, nil, nil
	}

	cond := policy.IdentityCondition
	if policy.RestrictUsers {
		cond = cfg.TargetIdentity
	}

	var trafficExpr, identityExpr string
	if cond != "" {
		if !strings.Contains(cond, "dns.") {
			trafficExpr = strings.Join(listItems, " or ")
			identityExpr = cond
		} else {
			wrapped := make([]string, len(listItems))
			for i, item := range listItems {
				wrapped[i] = fmt.Sprintf("(%s and %s)", cond, item)
			}
			trafficExpr = strings.Join(wrapped, " or ")
		}
	} else {
		trafficExpr = strings.Join(listItems, " or ")
	}

	var ruleEnabled bool
	if policy.Enabled != nil && !*policy.Enabled {
		ruleEnabled = false
	} else if cfg.AutoEnableRules {
		ruleEnabled = true
	} else if ruleIdx >= 0 {
		ruleEnabled = rules[ruleIdx].Enabled
	} else if policy.Enabled != nil {
		ruleEnabled = *policy.Enabled
	}

	blockPage := cfg.BlockPageEnabled
	if policy.BlockPageEnabled != nil {
		blockPage = *policy.BlockPageEnabled
	}
	ipCat := policy.IPCategories
	action := policy.resolvedAction()

	settings := map[string]any{}
	if ruleIdx >= 0 && rules[ruleIdx].RuleSettings != nil {
		for k, v := range rules[ruleIdx].RuleSettings {
			settings[k] = v
		}
	}
	settings["block_page_enabled"] = blockPage
	settings["ip_categories"] = ipCat

	payload := map[string]any{
		"name":          policy.Name,
		"action":        action,
		"enabled":       ruleEnabled,
		"filters":       []string{"dns"},
		"traffic":       trafficExpr,
		"rule_settings": settings,
	}
	if identityExpr != "" {
		payload["identity"] = identityExpr
	}

	if ruleIdx >= 0 {
		r := rules[ruleIdx]
		if isNonNullRaw(r.Precedence) {
			payload["precedence"] = r.Precedence
		}
		if isNonNullRaw(r.Description) {
			payload["description"] = r.Description
		}
		if isNonNullRaw(r.Schedule) {
			payload["schedule"] = r.Schedule
		}
		if isNonNullRaw(r.DevicePosture) {
			payload["device_posture"] = r.DevicePosture
		}

		oldBP, hasOldBP := r.RuleSettings["block_page_enabled"].(bool)
		oldIPCat, _ := r.RuleSettings["ip_categories"].(bool)
		settingsChanged := !hasOldBP || oldBP != blockPage || oldIPCat != ipCat

		changed := r.Traffic != trafficExpr ||
			r.Identity != identityExpr ||
			r.Enabled != ruleEnabled ||
			r.Action != action ||
			settingsChanged

		if changed {
			updated, err := cf.updateRule(r.ID, payload)
			if err != nil {
				return nil, nil, nil, err
			}
			if updated != nil {
				rules[ruleIdx] = *updated
			} else {
				rules[ruleIdx].Traffic = trafficExpr
				rules[ruleIdx].Identity = identityExpr
				rules[ruleIdx].Enabled = ruleEnabled
				rules[ruleIdx].Action = action
				rules[ruleIdx].RuleSettings = settings
			}
			logInfo("Updated firewall rule: %s (enabled=%t, block_page=%t, ip_categories=%t)",
				policy.Name, ruleEnabled, blockPage, ipCat)
		}
	} else {
		created, err := cf.createRule(payload)
		if err != nil {
			return nil, nil, nil, err
		}
		if created != nil {
			*existingRules = append(rules, *created)
		}
		logInfo("Created firewall rule: %s (enabled=%t, block_page=%t, ip_categories=%t)",
			policy.Name, ruleEnabled, blockPage, ipCat)
	}

	return activeIDs, surplusIDs, []string{policy.Name}, nil
}

func syncStandalonePolicies(cf *cloudflareAPI, cfg *appConfig, existingRules []gatewayRule) []string {
	var synced []string
	for ruleName, desiredVal := range cfg.Raw.GatewayPolicies {
		desiredEnabled, ok := desiredVal.(bool)
		if !ok {
			continue
		}
		idx := slices.IndexFunc(existingRules, func(r gatewayRule) bool { return r.Name == ruleName })
		if idx < 0 {
			continue
		}
		synced = append(synced, ruleName)
		matched := &existingRules[idx]

		if !cfg.AutoEnableRules && !matched.Enabled && desiredEnabled {
			logInfo("Skipping auto-enable for disabled standalone policy: %s", ruleName)
			continue
		}
		if matched.Enabled != desiredEnabled {
			payload := buildRuleUpdatePayload(*matched, desiredEnabled, matched.Traffic)
			if _, err := cf.updateRule(matched.ID, payload); err != nil {
				logErr("Failed to update standalone policy %s: %v", ruleName, err)
			} else {
				matched.Enabled = desiredEnabled
				state := "disabled"
				if desiredEnabled {
					state = "enabled"
				}
				logInfo("Updated standalone policy state: %s -> %s", ruleName, state)
			}
		}
	}
	return synced
}

func policyHasActiveRule(p policyConfig, entries []string, tldExpr string) bool {
	return len(entries) > 0 || (tldExpr != "" && p.UseSpamTLD) || compileCategoryExpression(p) != ""
}

func reclaimStaleResources(
	cf *cloudflareAPI,
	cfg *appConfig,
	compiled []compiledPolicy,
	tldExpr string,
	preservedListIDs map[string]struct{},
	preservedRuleNames map[string]struct{},
	existingLists *[]gatewayList,
	existingRules *[]gatewayRule,
) ([]gatewayRule, []string, error) {
	expectedRules := make(map[string]struct{}, len(preservedRuleNames)+len(compiled))
	for k := range preservedRuleNames {
		expectedRules[k] = struct{}{}
	}
	expectedChunks := make(map[string]int, len(compiled))
	for _, cp := range compiled {
		expectedChunks[cp.Policy.Prefix] = divCeil(len(cp.Entries), cfg.MaxListSize)
		if policyHasActiveRule(cp.Policy, cp.Entries, tldExpr) {
			expectedRules[cp.Policy.Name] = struct{}{}
		}
	}

	// 1. Delete orphaned rules first
	deletedRuleIDs := make(map[string]struct{})
	for _, r := range *existingRules {
		if cfg.isProtectedRule(r.Name) {
			continue
		}
		if _, ok := expectedRules[r.Name]; ok {
			continue
		}
		matchesScrub := false
		for _, t := range cfg.ScrubTargets {
			if strings.Contains(r.Name, t) {
				matchesScrub = true
				break
			}
		}
		if matchesScrub {
			if err := cf.deleteRule(r.ID); err != nil {
				logErr("Rule cleanup error (%s): %v", r.Name, err)
			} else {
				logInfo("Removed orphaned rule: %s", r.Name)
				deletedRuleIDs[r.ID] = struct{}{}
			}
		}
	}
	if len(deletedRuleIDs) > 0 {
		rules := *existingRules
		filtered := rules[:0]
		for _, r := range rules {
			if _, del := deletedRuleIDs[r.ID]; !del {
				filtered = append(filtered, r)
			}
		}
		*existingRules = filtered
		if !cf.dryRun {
			time.Sleep(2 * time.Second)
		}
	}

	// 2. Identify surplus chunks + removed policy lists
	keepIDs := make(map[string]struct{}, len(preservedListIDs))
	for k := range preservedListIDs {
		keepIDs[k] = struct{}{}
	}
	for prefix, needed := range expectedChunks {
		type indexedList struct {
			idx int
			id  string
		}
		var matched []indexedList
		for _, l := range *existingLists {
			if idx, ok := parseChunkIndex(l.Name, prefix); ok {
				matched = append(matched, indexedList{idx: idx, id: l.ID})
			}
		}
		slices.SortFunc(matched, func(a, b indexedList) int { return a.idx - b.idx })
		for _, m := range matched[:min(needed, len(matched))] {
			keepIDs[m.id] = struct{}{}
		}
	}

	var staleLists []gatewayList
	for _, l := range *existingLists {
		if _, keep := keepIDs[l.ID]; !keep && cfg.isManagedList(l.Name) {
			staleLists = append(staleLists, l)
		}
	}
	if len(staleLists) == 0 {
		return nil, nil, nil
	}

	logInfo("Pre-reclaiming %d stale/surplus list(s) before sync...", len(staleLists))
	staleIDs := make([]string, len(staleLists))
	for i, l := range staleLists {
		staleIDs[i] = l.ID
	}

	snapshots, err := detachListsFromRules(cf, staleIDs, existingRules)
	if err != nil {
		return nil, nil, err
	}

	deletedIDs := make([]string, 0, len(staleLists))
	for _, l := range staleLists {
		if err := deleteListWithRetry(cf, l, existingRules); err != nil {
			restoreDetachedRules(cf, snapshots, deletedIDs)
			return nil, nil, err
		}
		deletedIDs = append(deletedIDs, l.ID)
	}

	deletedSet := make(map[string]struct{}, len(deletedIDs))
	for _, id := range deletedIDs {
		deletedSet[id] = struct{}{}
	}
	lists := *existingLists
	filteredLists := lists[:0]
	for _, l := range lists {
		if _, del := deletedSet[l.ID]; !del {
			filteredLists = append(filteredLists, l)
		}
	}
	*existingLists = filteredLists

	return snapshots, deletedIDs, nil
}

func cleanupOrphans(
	cf *cloudflareAPI,
	cfg *appConfig,
	existingLists []gatewayList,
	existingRules *[]gatewayRule,
	activeIDs, surplusIDs, activeRules []string,
) error {
	activeRuleSet := make(map[string]struct{}, len(activeRules))
	for _, r := range activeRules {
		activeRuleSet[r] = struct{}{}
	}

	deletedRuleIDs := make(map[string]struct{})
	for _, r := range *existingRules {
		if cfg.isProtectedRule(r.Name) {
			continue
		}
		if _, ok := activeRuleSet[r.Name]; ok {
			continue
		}
		matchesScrub := false
		for _, t := range cfg.ScrubTargets {
			if strings.Contains(r.Name, t) {
				matchesScrub = true
				break
			}
		}
		if matchesScrub {
			if err := cf.deleteRule(r.ID); err != nil {
				logErr("Rule cleanup error (%s): %v", r.Name, err)
			} else {
				deletedRuleIDs[r.ID] = struct{}{}
				logInfo("Removed orphaned rule: %s", r.Name)
			}
		}
	}

	if len(deletedRuleIDs) > 0 {
		rules := *existingRules
		filtered := rules[:0]
		for _, r := range rules {
			if _, del := deletedRuleIDs[r.ID]; !del {
				filtered = append(filtered, r)
			}
		}
		*existingRules = filtered
	}
	if (len(deletedRuleIDs) > 0 || len(surplusIDs) > 0) && !cf.dryRun {
		time.Sleep(2 * time.Second)
	}

	activeSet := make(map[string]struct{}, len(activeIDs))
	for _, id := range activeIDs {
		activeSet[id] = struct{}{}
	}
	surplusSet := make(map[string]struct{}, len(surplusIDs))
	for _, id := range surplusIDs {
		surplusSet[id] = struct{}{}
	}

	var listsToDelete []gatewayList
	for _, l := range existingLists {
		_, isSurplus := surplusSet[l.ID]
		_, isActive := activeSet[l.ID]
		if isSurplus || (!isActive && cfg.isManagedList(l.Name)) {
			listsToDelete = append(listsToDelete, l)
		}
	}
	if len(listsToDelete) == 0 {
		return nil
	}

	idsToDetach := make([]string, len(listsToDelete))
	for i, l := range listsToDelete {
		idsToDetach[i] = l.ID
	}
	snapshots, err := detachListsFromRules(cf, idsToDetach, existingRules)
	if err != nil {
		return err
	}

	deletedIDs := make([]string, 0, len(listsToDelete))
	for _, l := range listsToDelete {
		if err := deleteListWithRetry(cf, l, existingRules); err != nil {
			restoreDetachedRules(cf, snapshots, deletedIDs)
			return err
		}
		deletedIDs = append(deletedIDs, l.ID)
	}
	return nil
}

func filterPolicyIncludes(policies []policyConfig, keep func(string) bool) {
	for i := range policies {
		inc := policies[i].Include
		filtered := inc[:0]
		for _, s := range inc {
			if keep(s) {
				filtered = append(filtered, s)
			}
		}
		policies[i].Include = filtered
	}
}

func sumStats(compiled []compiledPolicy, maxListSize int) (int, int) {
	entries, chunks := 0, 0
	for _, cp := range compiled {
		entries += len(cp.Entries)
		chunks += divCeil(len(cp.Entries), maxListSize)
	}
	return entries, chunks
}

func run() error {
	start := time.Now()

	configPath := flag.String("config", "config.toml", "Path to config.toml")
	dryRun := flag.Bool("dry-run", false, "Preview planned Cloudflare changes without mutating")
	forceRefresh := flag.Bool("force-refresh-relevance", false, "Force rebuild of relevance cache")
	strictFeeds := flag.Bool("strict", false, "Exit non-zero if any upstream feed fails")
	flag.Parse()

	cfg, err := loadConfig(*configPath, *dryRun, *forceRefresh, *strictFeeds)
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
	useSpamTLDAny := false
	for _, k := range policyKeys {
		p := cfg.Raw.Policies[k]
		if p.UseSpamTLD {
			useSpamTLDAny = true
		}
		allPolicies = append(allPolicies, p)
	}

	domainSources := parseSources(cfg.Raw.Sources, false)
	ipSources := parseSources(cfg.Raw.IPSources, true)

	if useSpamTLDAny && cfg.Raw.SpamAllowSource != nil && cfg.Raw.SpamAllowSource.Name != "" {
		sa := cfg.Raw.SpamAllowSource
		allPolicies = append(allPolicies, policyConfig{
			Prefix:  "L_AllowSpam",
			Name:    "Allow: Spam Exceptions",
			Type:    "DOMAIN",
			Action:  "allow",
			Include: []string{sa.Name},
		})
		enableRel := false
		if sa.Relevance != nil {
			enableRel = *sa.Relevance
		}
		domainSources = append(domainSources, sourceSpec{
			Name:            sa.Name,
			URLs:            []string{sa.URL},
			EnableRelevance: enableRel,
		})
	}

	feedClient := newHTTPClient(90 * time.Second)

	needsRelevance := slices.ContainsFunc(domainSources, func(s sourceSpec) bool { return s.EnableRelevance })
	var relSet *relevanceSet
	relevanceStatus := "unused"
	if needsRelevance {
		relSet, relevanceStatus, err = resolveRelevanceDataset(feedClient, cfg)
		if err != nil {
			return err
		}
	}

	tldExpr := ""
	var spamTLDs map[string]struct{}
	tldFailed := false
	if cfg.Raw.TLD.URL != "" && useSpamTLDAny {
		tldExpr, spamTLDs, err = fetchSpamTLDs(feedClient, cfg.Raw.TLD.URL)
		if err != nil {
			logErr("Spam TLD feed failure (%s): %v. Preserving TLD-dependent policies.", cfg.Raw.TLD.URL, err)
			tldFailed = true
		}
	}

	// Fault-tolerant parallel feed fetching
	type feedOutcome struct {
		name string
		feed fetchedFeed
		err  error
	}
	totalSources := len(domainSources) + len(ipSources)
	outcomes := make([]feedOutcome, totalSources)
	sem := make(chan struct{}, cfg.MaxWorkers)
	var wg sync.WaitGroup

	for i, spec := range domainSources {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, spec sourceSpec) {
			defer wg.Done()
			defer func() { <-sem }()
			var rel *relevanceSet
			if spec.EnableRelevance {
				rel = relSet
			}
			kept, err := fetchFeedSource(feedClient, spec, rel)
			if err == nil && len(kept) == 0 {
				err = fmt.Errorf("feed '%s' returned 0 valid domains", spec.Name)
			}
			outcomes[i] = feedOutcome{name: spec.Name, feed: fetchedFeed{Domains: kept}, err: err}
		}(i, spec)
	}

	for j, spec := range ipSources {
		idx := len(domainSources) + j
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, spec sourceSpec) {
			defer wg.Done()
			defer func() { <-sem }()
			nets, err := fetchIPSource(feedClient, spec)
			if err == nil && len(nets) == 0 {
				err = fmt.Errorf("IP feed '%s' returned 0 valid subnets", spec.Name)
			}
			outcomes[idx] = feedOutcome{name: spec.Name, feed: fetchedFeed{IsIP: true, IPs: nets}, err: err}
		}(idx, spec)
	}
	wg.Wait()

	// Release relevance slice RAM immediately before Cloudflare API sync
	relSet = nil
	runtime.GC()

	fetched := make(map[string]fetchedFeed, totalSources)
	failedFeeds := make(map[string]struct{})
	for _, o := range outcomes {
		if o.err != nil {
			logErr("Upstream feed '%s' failed: %v. Policies using it will be preserved as-is.", o.name, o.err)
			failedFeeds[o.name] = struct{}{}
		} else {
			fetched[o.name] = o.feed
		}
	}

	if totalSources > 0 && len(fetched) == 0 {
		return fmt.Errorf("all %d upstream feeds failed; aborting without touching Cloudflare", totalSources)
	}

	var activePolicies, preservedPolicies []policyConfig
	for _, p := range allPolicies {
		missingDep := false
		for _, src := range p.Include {
			if _, bad := failedFeeds[src]; bad {
				missingDep = true
				break
			}
		}
		if !missingDep {
			for _, src := range p.Exclude {
				if _, bad := failedFeeds[src]; bad {
					missingDep = true
					break
				}
			}
		}
		if missingDep || (p.UseSpamTLD && tldFailed) {
			logWarn("Preserving existing Cloudflare state for policy '%s' due to upstream feed failure.", p.Name)
			preservedPolicies = append(preservedPolicies, p)
		} else {
			activePolicies = append(activePolicies, p)
		}
	}

	existingLists, err := cf.getLists()
	if err != nil {
		return err
	}
	existingRules, err := cf.getRules()
	if err != nil {
		return err
	}

	preservedListIDs := make(map[string]struct{})
	preservedRuleNames := make(map[string]struct{})
	preservedItemsCount := 0
	for _, p := range preservedPolicies {
		preservedRuleNames[p.Name] = struct{}{}
		for _, l := range existingLists {
			if _, ok := parseChunkIndex(l.Name, p.Prefix); ok {
				preservedListIDs[l.ID] = struct{}{}
				if l.Count != nil {
					preservedItemsCount += int(*l.Count)
				}
			}
		}
	}

	unmanagedListsCount := 0
	currentManagedItems := 0
	for _, l := range existingLists {
		if cfg.isManagedList(l.Name) {
			if l.Count != nil {
				currentManagedItems += int(*l.Count)
			}
		} else {
			unmanagedListsCount++
		}
	}

	maxActiveLists := max(maxCloudflareLists-unmanagedListsCount-len(preservedListIDs), 0)
	activeQuota := max(cfg.TotalQuota-preservedItemsCount, 0)
	hasActiveSpamTLD := useSpamTLDAny && !tldFailed

	compiled := buildPolicySets(cfg, activePolicies, fetched, spamTLDs, hasActiveSpamTLD)
	activeEntries, estimatedChunks := sumStats(compiled, cfg.MaxListSize)

	// Fallback Tier 1: Shed OISD NSFW
	if activeEntries > activeQuota || estimatedChunks > maxActiveLists {
		logWarn("Capacity constraint reached (Entries: %d/%d, Estimated Lists: %d/%d). Shedding OISD NSFW...",
			activeEntries, activeQuota, estimatedChunks, maxActiveLists)
		filterPolicyIncludes(activePolicies, func(inc string) bool {
			l := strings.ToLower(inc)
			return !(strings.Contains(l, "oisd") && strings.Contains(l, "nsfw"))
		})
		compiled = buildPolicySets(cfg, activePolicies, fetched, spamTLDs, hasActiveSpamTLD)
		activeEntries, estimatedChunks = sumStats(compiled, cfg.MaxListSize)
	}

	// Fallback Tier 2: Shed HaGeZi TIF IPs
	if activeEntries > activeQuota || estimatedChunks > maxActiveLists {
		logWarn("Capacity still exceeded (Entries: %d/%d, Estimated Lists: %d/%d). Shedding HaGeZi TIF IPs...",
			activeEntries, activeQuota, estimatedChunks, maxActiveLists)
		filterPolicyIncludes(activePolicies, func(inc string) bool {
			l := strings.ToLower(inc)
			return !(strings.Contains(l, "tif") && strings.Contains(l, "ip"))
		})
		compiled = buildPolicySets(cfg, activePolicies, fetched, spamTLDs, hasActiveSpamTLD)
		activeEntries, estimatedChunks = sumStats(compiled, cfg.MaxListSize)
	}

	// Fallback Tier 3: Shed HaGeZi TIF domains
	if activeEntries > activeQuota || estimatedChunks > maxActiveLists {
		logWarn("Capacity still exceeded (Entries: %d/%d, Estimated Lists: %d/%d). Shedding HaGeZi TIF domain feeds...",
			activeEntries, activeQuota, estimatedChunks, maxActiveLists)
		filterPolicyIncludes(activePolicies, func(inc string) bool {
			return !strings.Contains(strings.ToLower(inc), "tif")
		})
		compiled = buildPolicySets(cfg, activePolicies, fetched, spamTLDs, hasActiveSpamTLD)
		activeEntries, estimatedChunks = sumStats(compiled, cfg.MaxListSize)
	}

	if activeEntries > activeQuota || estimatedChunks > maxActiveLists {
		return fmt.Errorf("capacity exceeded after all fallback tiers (Active Entries: %d/%d, Active Lists: %d/%d)",
			activeEntries, activeQuota, estimatedChunks, maxActiveLists)
	}

	logInfo("Cloudflare lists: %d total (%d unmanaged, %d preserved, %d live items). Syncing %d list(s) in place...",
		len(existingLists), unmanagedListsCount, len(preservedListIDs), currentManagedItems, estimatedChunks)

	standaloneRules := syncStandalonePolicies(cf, cfg, existingRules)

	reclaimSnapshots, reclaimedIDs, err := reclaimStaleResources(
		cf, cfg, compiled, tldExpr, preservedListIDs, preservedRuleNames, &existingLists, &existingRules,
	)
	if err != nil {
		return err
	}

	initTracking := func() ([]string, []string, []string) {
		actIDs := make([]string, 0, len(preservedListIDs)+estimatedChunks)
		for id := range preservedListIDs {
			actIDs = append(actIDs, id)
		}
		actRules := make([]string, 0, len(standaloneRules)+len(preservedRuleNames)+len(compiled))
		actRules = append(actRules, standaloneRules...)
		for name := range preservedRuleNames {
			actRules = append(actRules, name)
		}
		return actIDs, nil, actRules
	}

	allActiveIDs, allSurplusIDs, allActiveRules := initTracking()

	runSync := func(sets []compiledPolicy, elists []gatewayList, erules *[]gatewayRule) error {
		for _, cp := range sets {
			expr := ""
			if cp.Policy.UseSpamTLD {
				expr = tldExpr
			}
			aIDs, sIDs, rNames, syncErr := syncPolicyInPlace(cf, cfg, elists, erules, cp.Entries, cp.Policy, expr)
			if syncErr != nil {
				return syncErr
			}
			allActiveIDs = append(allActiveIDs, aIDs...)
			allSurplusIDs = append(allSurplusIDs, sIDs...)
			allActiveRules = append(allActiveRules, rNames...)
		}
		return nil
	}

	if syncErr := runSync(compiled, existingLists, &existingRules); syncErr != nil {
		errStr := syncErr.Error()
		if strings.Contains(errStr, "Maximum number of lists reached") || strings.Contains(errStr, "2017") {
			logErr("Cloudflare list limit (300) hit during sync! Forcing emergency OISD NSFW & TIF purge and list reclamation...")
			existingLists, err = cf.getLists()
			if err != nil {
				return err
			}
			existingRules, err = cf.getRules()
			if err != nil {
				return err
			}

			var reclaimable []gatewayList
			var reclaimableIDs []string
			for _, l := range existingLists {
				if _, pres := preservedListIDs[l.ID]; !pres && cfg.isManagedList(l.Name) {
					reclaimable = append(reclaimable, l)
					reclaimableIDs = append(reclaimableIDs, l.ID)
				}
			}

			ruleSnapshots, detachErr := detachListsFromRules(cf, reclaimableIDs, &existingRules)
			if detachErr != nil {
				return detachErr
			}
			deletedIDs := make([]string, 0, len(reclaimable))

			recoveryErr := func() error {
				for _, l := range reclaimable {
					if err := deleteListWithRetry(cf, l, &existingRules); err != nil {
						return err
					}
					deletedIDs = append(deletedIDs, l.ID)
				}
				if !cf.dryRun {
					time.Sleep(3 * time.Second)
				}

				filterPolicyIncludes(activePolicies, func(inc string) bool {
					l := strings.ToLower(inc)
					return !(strings.Contains(l, "oisd") && strings.Contains(l, "nsfw")) && !strings.Contains(l, "tif")
				})
				compiled = buildPolicySets(cfg, activePolicies, fetched, spamTLDs, hasActiveSpamTLD)
				activeEntries, _ = sumStats(compiled, cfg.MaxListSize)

				existingLists, err = cf.getLists()
				if err != nil {
					return err
				}
				existingRules, err = cf.getRules()
				if err != nil {
					return err
				}

				allActiveIDs, allSurplusIDs, allActiveRules = initTracking()
				return runSync(compiled, existingLists, &existingRules)
			}()

			if recoveryErr != nil {
				restoreDetachedRules(cf, ruleSnapshots, deletedIDs)
				return recoveryErr
			}
		} else {
			restoreDetachedRules(cf, reclaimSnapshots, reclaimedIDs)
			return syncErr
		}
	}

	if err := cleanupOrphans(cf, cfg, existingLists, &existingRules, allActiveIDs, allSurplusIDs, allActiveRules); err != nil {
		return err
	}

	failedTotal := len(failedFeeds)
	if tldFailed {
		failedTotal++
	}
	logInfo("Sync finished in %.2fs | relevance=%s | policies_synced=%d preserved=%d | feeds_ok=%d failed=%d | items=%d lists=%d",
		time.Since(start).Seconds(),
		relevanceStatus,
		len(compiled),
		len(preservedPolicies),
		len(fetched),
		failedTotal,
		activeEntries+preservedItemsCount,
		len(allActiveIDs),
	)

	if cfg.StrictFeeds && failedTotal > 0 {
		return fmt.Errorf("--strict enabled and %d upstream feed(s) failed", failedTotal)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		logErr("%v", err)
		os.Exit(1)
	}
}
