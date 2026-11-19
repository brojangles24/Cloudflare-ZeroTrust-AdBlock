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
	cacheMagicV1           = "RELCAC01"
	cacheMagicV2           = "RELCAC02"
	cacheMagicV3           = "RELCAC03"
	spamAllowRuleName      = "Allow: Spam Exceptions"
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

// Exact root domains (and their www. variants) stripped from block policies
// to prevent upstream feed poisoning from knocking out core infrastructure.
// Subdomains (e.g., ads.google.com, telemetry.microsoft.com) are NOT exempted.
var defaultNeverBlock = []string{
	"cloudflare.com",
	"cloudflare-dns.com",
	"one.one.one.one",
	"github.com",
	"githubusercontent.com",
	"raw.githubusercontent.com",
	"cdn.jsdelivr.net",
	"google.com",
	"googleapis.com",
	"gstatic.com",
	"apple.com",
	"icloud.com",
	"microsoft.com",
	"windowsupdate.com",
	"live.com",
	"tailscale.com",
	"amazonaws.com",
	"quad9.net",
	"digicert.com",
	"letsencrypt.org",
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
	ProtectedRules           []string `toml:"protected_rules"`
	UnmanagedListKeywords    []string `toml:"unmanaged_list_keywords"`
	NeverBlock               []string `toml:"never_block"`
	DisableDefaultNeverBlock bool     `toml:"disable_default_never_block"`
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

func (p policyConfig) isScoped(cfg *appConfig) bool {
	return p.effectiveIdentity(cfg) != ""
}

// isTrimmable defaults to true ONLY for dynamic bulk Porn/NSFW and Malware/Badware/TIF policies.
// Static safety policies (Bypass, AdBlock, Social, Piracy, IP lists, Allow lists) are
// protected from rank trimming unless explicitly opted in via `trimmable = true`.
func (p policyConfig) isTrimmable() bool {
	if p.resolvedAction() == "allow" || p.resolvedType() == "IP" {
		return false
	}
	if p.Trimmable != nil {
		return *p.Trimmable
	}
	var sb strings.Builder
	sb.WriteString(strings.ToLower(p.Name))
	sb.WriteByte(' ')
	sb.WriteString(strings.ToLower(p.Prefix))
	for _, inc := range p.Include {
		sb.WriteByte(' ')
		sb.WriteString(strings.ToLower(inc))
	}
	full := sb.String()
	return strings.Contains(full, "porn") ||
		strings.Contains(full, "nsfw") ||
		strings.Contains(full, "adult") ||
		strings.Contains(full, "malware") ||
		strings.Contains(full, "tif") ||
		strings.Contains(full, "threat") ||
		strings.Contains(full, "badware")
}

// resolvedPriority assigns lower numbers (higher priority) to static safety lists
// (Bypass -> AdBlock -> Social -> Piracy -> IPs -> Other) and higher numbers to
// trimmable bulk lists (Malware=80, Badware=85, Porn=90).
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
	ProtectedRules          map[string]struct{}
	UnmanagedListKeywords   []string
	NeverBlock              map[string]struct{}
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

func (c *appConfig) isNeverBlocked(domain string) bool {
	if _, ok := c.NeverBlock[domain]; ok {
		return true
	}
	if trimmed, ok := strings.CutPrefix(domain, "www."); ok {
		if _, ok := c.NeverBlock[trimmed]; ok {
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

	neverBlock := make(map[string]struct{}, len(defaultNeverBlock)+len(s.NeverBlock))
	if !s.DisableDefaultNeverBlock {
		for _, d := range defaultNeverBlock {
			neverBlock[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}
	}
	for _, d := range s.NeverBlock {
		if clean, ok := normalizeDomain(d); ok {
			neverBlock[clean] = struct{}{}
		}
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
		ProtectedRules:          protected,
		UnmanagedListKeywords:   unmanagedKeywords,
		NeverBlock:              neverBlock,
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

func (r gatewayRule) isDNSRule() bool {
	return len(r.Filters) == 0 || slices.Contains(r.Filters, "dns")
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

func parseRulePrecedence(raw json.RawMessage) (int64, bool) {
	if !isNonNullRaw(raw) {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return int64(f), true
	}
	return 0, false
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

func hasParentDomain[V any](host string, lookup map[string]V) bool {
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

func hasSuffixDomain[V any](host string, lookup map[string]V) bool {
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

// ---------- Rank-Aware Flat Relevance Set & Binary Cache (RELCAC03) ----------

type rankedHash struct {
	hash uint64
	rank uint32
}

type relevanceSet struct {
	hashes []uint64
	ranks  []uint32
}

func (rs *relevanceSet) len() int {
	if rs == nil {
		return 0
	}
	return len(rs.hashes)
}

func (rs *relevanceSet) bestRank(host string) (uint32, bool) {
	if rs == nil || len(rs.hashes) == 0 {
		return unrankedRank, false
	}
	best := unrankedRank
	found := false

	if idx, ok := slices.BinarySearch(rs.hashes, xxh3.HashString(host)); ok {
		best = rs.ranks[idx]
		found = true
	}
	rest := host
	for {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		parent := rest[dot+1:]
		if !strings.ContainsRune(parent, '.') {
			break
		}
		if idx, ok := slices.BinarySearch(rs.hashes, xxh3.HashString(parent)); ok {
			if rs.ranks[idx] < best {
				best = rs.ranks[idx]
			}
			found = true
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
	copy(hdr[:8], cacheMagicV3)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(len(rs.hashes)))
	if _, err := bw.Write(hdr[:]); err != nil {
		f.Close()
		return err
	}

	hashBuf := make([]byte, 8192*8)
	for i := 0; i < len(rs.hashes); i += 8192 {
		end := min(i+8192, len(rs.hashes))
		nBytes := (end - i) * 8
		for j, h := range rs.hashes[i:end] {
			binary.LittleEndian.PutUint64(hashBuf[j*8:(j+1)*8], h)
		}
		_, _ = hasher.Write(hashBuf[:nBytes])
		if _, err := bw.Write(hashBuf[:nBytes]); err != nil {
			f.Close()
			return err
		}
	}

	rankBuf := make([]byte, 8192*4)
	for i := 0; i < len(rs.ranks); i += 8192 {
		end := min(i+8192, len(rs.ranks))
		nBytes := (end - i) * 4
		for j, r := range rs.ranks[i:end] {
			binary.LittleEndian.PutUint32(rankBuf[j*4:(j+1)*4], r)
		}
		_, _ = hasher.Write(rankBuf[:nBytes])
		if _, err := bw.Write(rankBuf[:nBytes]); err != nil {
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

func loadRelevanceCache(cacheDir string, allowLegacy bool) (*relevanceSet, error) {
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
	count := binary.LittleEndian.Uint64(hdr[8:16])
	if count < minRelevanceDomains {
		return nil, fmt.Errorf("relevance cache count (%d) below minimum threshold", count)
	}

	switch magic {
	case cacheMagicV3:
		expectedLen := int64(count)*12 + 24
		if stat.Size() != expectedLen {
			return nil, fmt.Errorf("relevance v3 cache truncated (expected %d bytes, got %d)", expectedLen, stat.Size())
		}
		hashes := make([]uint64, count)
		ranks := make([]uint32, count)
		hasher := xxh3.New()

		hashBuf := make([]byte, 8192*8)
		var prev uint64
		for i := 0; i < int(count); i += 8192 {
			take := min(8192, int(count)-i)
			nBytes := take * 8
			if _, err := io.ReadFull(br, hashBuf[:nBytes]); err != nil {
				return nil, err
			}
			_, _ = hasher.Write(hashBuf[:nBytes])
			for j := 0; j < take; j++ {
				v := binary.LittleEndian.Uint64(hashBuf[j*8 : (j+1)*8])
				if i+j > 0 && v < prev {
					return nil, errors.New("relevance v3 cache hashes are not sorted")
				}
				prev = v
				hashes[i+j] = v
			}
		}

		rankBuf := make([]byte, 8192*4)
		for i := 0; i < int(count); i += 8192 {
			take := min(8192, int(count)-i)
			nBytes := take * 4
			if _, err := io.ReadFull(br, rankBuf[:nBytes]); err != nil {
				return nil, err
			}
			_, _ = hasher.Write(rankBuf[:nBytes])
			for j := 0; j < take; j++ {
				ranks[i+j] = binary.LittleEndian.Uint32(rankBuf[j*4 : (j+1)*4])
			}
		}

		var trailer [8]byte
		if _, err := io.ReadFull(br, trailer[:]); err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint64(trailer[:]) != hasher.Sum64() {
			return nil, errors.New("relevance v3 cache checksum mismatch (corrupted file)")
		}
		return &relevanceSet{hashes: hashes, ranks: ranks}, nil

	case cacheMagicV2, cacheMagicV1:
		if !allowLegacy {
			return nil, fmt.Errorf("legacy cache format %s detected; upgrading to %s with popularity ranks", magic, cacheMagicV3)
		}
		expectedLen := int64(count)*8 + 24
		if stat.Size() != expectedLen {
			return nil, fmt.Errorf("legacy relevance cache truncated (expected %d bytes, got %d)", expectedLen, stat.Size())
		}
		hashes := make([]uint64, count)
		hasher := xxh3.New()
		buf := make([]byte, 8192*8)
		for i := 0; i < int(count); i += 8192 {
			take := min(8192, int(count)-i)
			nBytes := take * 8
			if _, err := io.ReadFull(br, buf[:nBytes]); err != nil {
				return nil, err
			}
			_, _ = hasher.Write(buf[:nBytes])
			for j := 0; j < take; j++ {
				hashes[i+j] = binary.LittleEndian.Uint64(buf[j*8 : (j+1)*8])
			}
		}
		var trailer [8]byte
		if _, err := io.ReadFull(br, trailer[:]); err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint64(trailer[:]) != hasher.Sum64() {
			return nil, errors.New("legacy relevance cache checksum mismatch")
		}
		slices.Sort(hashes)
		hashes = slices.Compact(hashes)
		ranks := make([]uint32, len(hashes))
		for i := range ranks {
			ranks[i] = unrankedRank
		}
		return &relevanceSet{hashes: hashes, ranks: ranks}, nil

	default:
		return nil, fmt.Errorf("invalid relevance cache magic header: %q", magic)
	}
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

// ---------- Feed Fetching, HTML Guardrail, & Parsing ----------

func looksLikeHTMLOrXML(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return true
	}
	sample := body
	if len(sample) > 512 {
		sample = sample[:512]
	}
	sample = bytes.TrimPrefix(sample, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	trimmed := strings.ToLower(strings.TrimSpace(string(sample)))
	return strings.HasPrefix(trimmed, "<!doctype") ||
		strings.HasPrefix(trimmed, "<html") ||
		strings.HasPrefix(trimmed, "<head") ||
		strings.HasPrefix(trimmed, "<body") ||
		strings.HasPrefix(trimmed, "<?xml")
}

func fetchWithRetryMeta(client *http.Client, url string, checkBodyHTML bool) ([]byte, string, error) {
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("User-Agent", uaStr)
		resp, err := client.Do(req)
		if err == nil {
			ct := resp.Header.Get("Content-Type")
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				err = readErr
			} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			} else if strings.Contains(strings.ToLower(ct), "text/html") || strings.Contains(strings.ToLower(ct), "application/xhtml") {
				err = fmt.Errorf("HTML response rejected (Content-Type: %s)", ct)
			} else if checkBodyHTML && looksLikeHTMLOrXML(ct, body) {
				err = errors.New("HTML/XML error page detected in feed body")
			} else {
				return body, extractHeaderFingerprint(resp.Header), nil
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
	b, _, err := fetchWithRetryMeta(client, url, true)
	return b, err
}

func sortAndCompactRanked(items []rankedHash) []rankedHash {
	slices.SortFunc(items, func(a, b rankedHash) int {
		if c := cmp.Compare(a.hash, b.hash); c != 0 {
			return c
		}
		return cmp.Compare(a.rank, b.rank)
	})
	return slices.CompactFunc(items, func(a, b rankedHash) bool {
		return a.hash == b.hash
	})
}

func parseCSVStream(r io.Reader, col int, skipHeader bool) []rankedHash {
	var items []rankedHash
	br := bufio.NewReaderSize(r, 64*1024)
	rowIdx := 0
	var rank uint32
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			curIdx := rowIdx
			rowIdx++
			if !(skipHeader && curIdx == 0) {
				rank++
				if rawCol, ok := nthCSVCol(line, col); ok {
					trimmed := strings.Trim(strings.TrimSpace(rawCol), `"`)
					if trimmed != "" {
						if clean, ok := normalizeDomain(trimmed); ok {
							items = append(items, rankedHash{
								hash: xxh3.HashString(clean),
								rank: rank,
							})
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	return sortAndCompactRanked(items)
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
	logInfo("Fetching fresh ranked relevance datasets directly from sources...")
	type itemResult struct {
		url   string
		fp    string
		items []rankedHash
	}
	results := make([]itemResult, len(defaultTopLists))
	var wg sync.WaitGroup

	for i, spec := range defaultTopLists {
		wg.Add(1)
		go func(i int, spec topListSpec) {
			defer wg.Done()
			rawBytes, fp, err := fetchWithRetryMeta(client, spec.URL, spec.Compression == "raw")
			if err != nil {
				logWarn("Failed to fetch top list (%s): %v", spec.URL, err)
				results[i] = itemResult{url: spec.URL}
				return
			}

			var parsed []rankedHash
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

			logInfo("Fetched & parsed %d ranked domains from %s", len(parsed), spec.URL)
			results[i] = itemResult{url: spec.URL, fp: fp, items: parsed}
		}(i, spec)
	}
	wg.Wait()

	headersMap := make(map[string]string, len(results))
	totalCap := 0
	for _, r := range results {
		if r.fp != "" {
			headersMap[r.url] = r.fp
		}
		totalCap += len(r.items)
	}

	merged := make([]rankedHash, 0, totalCap)
	for i := range results {
		merged = append(merged, results[i].items...)
		results[i].items = nil
	}
	merged = sortAndCompactRanked(merged)

	if len(merged) < minRelevanceDomains {
		return nil, nil, fmt.Errorf("relevance dataset critically low (%d domains)", len(merged))
	}

	hashes := make([]uint64, len(merged))
	ranks := make([]uint32, len(merged))
	for i, it := range merged {
		hashes[i] = it.hash
		ranks[i] = it.rank
	}
	merged = nil

	logInfo("Ranked relevance dataset compiled: %d hashed root domains.", len(hashes))
	return &relevanceSet{hashes: hashes, ranks: ranks}, headersMap, nil
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

	if !cfg.ForceRefreshRelevance && cachedMeta != nil && cachedMeta.Version >= 3 {
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
			rs, err := loadRelevanceCache(cfg.RelevanceCacheDir, false)
			if err == nil {
				logInfo("Loaded %d ranked root domains from relevance cache.", rs.len())
				return rs, "cache-hit", nil
			}
			logWarn("Cached relevance.bin unusable (%v); rebuilding from upstream.", err)
		}
	} else if binExists && cachedMeta != nil && cachedMeta.Version < 3 {
		logInfo("Upgrading relevance cache from v%d to v3 (rank-aware format)...", cachedMeta.Version)
	}

	rs, sourceHeaders, err := buildFreshRelevanceDataset(client)
	if err == nil {
		meta := &relevanceMeta{
			Version:       3,
			CreatedAt:     now,
			DomainCount:   rs.len(),
			SourceHeaders: sourceHeaders,
		}
		if saveErr := saveRelevanceCache(cfg.RelevanceCacheDir, rs, meta); saveErr != nil {
			logWarn("Failed writing relevance cache to %s: %v (continuing sync)", cfg.RelevanceCacheDir, saveErr)
		} else {
			logInfo("Saved ranked relevance cache to %s (%d entries).", cfg.RelevanceCacheDir, rs.len())
		}
		return rs, "refreshed", nil
	}

	if binExists {
		logWarn("Fresh relevance fetch failed (%v). Attempting fallback to existing stale cache...", err)
		if stale, loadErr := loadRelevanceCache(cfg.RelevanceCacheDir, true); loadErr == nil {
			logWarn("Self-healed using stale relevance cache (%d entries) to keep sync running.", stale.len())
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

func ingestDomainToken(rawTok string, rel *relevanceSet, enforceRelevance bool, kept map[string]uint32) {
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

	rank := unrankedRank
	if rel != nil {
		checkDom := strings.TrimPrefix(clean, "www.")
		best, found := rel.bestRank(checkDom)
		if enforceRelevance && !found {
			return
		}
		if found {
			rank = best
		}
	}
	kept[clean] = rank
}

func fetchFeedSource(client *http.Client, spec sourceSpec, rel *relevanceSet) (map[string]uint32, error) {
	kept := make(map[string]uint32)
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
									ingestDomainToken(tok, rel, spec.EnableRelevance, kept)
								}
							} else {
								ingestDomainToken(fields[len(fields)-1], rel, spec.EnableRelevance, kept)
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
	logInfo("Fetched %s: %d kept (relevance=%t)", spec.Name, len(kept), spec.EnableRelevance)
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

// ---------- Policy Compilation, Cross-Policy Dedup, Rank Trimming, & Hash Bucketing ----------

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
	Policy       policyConfig
	Priority     int
	Trimmable    bool
	Entries      []rankedEntry
	Chunks       [][]string
	RawCount     int
	DedupedCount int
	TrimmedCount int
	GuardedCount int
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
				rawSets[i] = rawPolicySet{
					policy:    p.clone(),
					priority:  prio,
					trimmable: false,
					ips:       collapsed,
					rawCount:  len(collapsed),
				}
				return
			}

			pSet := make(map[string]uint32)
			for _, inc := range p.Include {
				if feed, ok := fetched[inc]; ok && !feed.IsIP {
					for d, r := range feed.Domains {
						if prev, exists := pSet[d]; !exists || r < prev {
							pSet[d] = r
						}
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

			var guardedHits []string
			guardedCount := 0
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
				for d := range pSet {
					if cfg.isNeverBlocked(d) {
						delete(pSet, d)
						guardedCount++
						guardedHits = append(guardedHits, fmt.Sprintf("%s (%s)", d, p.Name))
					}
				}
			}

			for d := range pSet {
				if hasParentDomain(d, pSet) {
					delete(pSet, d)
				}
			}

			rawSets[i] = rawPolicySet{
				policy:       p.clone(),
				priority:     prio,
				trimmable:    p.isTrimmable(),
				domains:      pSet,
				rawCount:     len(pSet),
				guardedCount: guardedCount,
				guardedHits:  guardedHits,
			}
		}(i, pol)
	}
	wg.Wait()

	var guardWarnings []string
	for _, rs := range rawSets {
		guardWarnings = append(guardWarnings, rs.guardedHits...)
	}
	if len(guardWarnings) > 0 {
		slices.Sort(guardWarnings)
		logWarn("Safety floor stripped %d protected root domain(s): %s", len(guardWarnings), strings.Join(guardWarnings, ", "))
	}

	// Step 2: Priority-ordered cross-policy deduplication.
	// Protected policies NEVER dedup against trimmable policies so rank trimming
	// Porn/Badware/Malware can never accidentally unblock a static safety domain.
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

	globalStableBlocked := make(map[string]struct{})
	globalAllBlocked := make(map[string]struct{})
	scopedStableBlocked := make(map[string]map[string]struct{})
	scopedAllBlocked := make(map[string]map[string]struct{})
	dedupCounts := make([]int, len(rawSets))

	// Pass 2a: Global domain block policies
	for _, idx := range order {
		rs := &rawSets[idx]
		if rs.policy.resolvedType() != "DOMAIN" || rs.policy.resolvedAction() == "allow" || rs.policy.isScoped(cfg) {
			continue
		}
		targetLookup := globalStableBlocked
		if rs.trimmable {
			targetLookup = globalAllBlocked
		}
		removed := 0
		for d := range rs.domains {
			if hasSuffixDomain(d, targetLookup) {
				delete(rs.domains, d)
				removed++
			}
		}
		dedupCounts[idx] = removed
		for d := range rs.domains {
			globalAllBlocked[d] = struct{}{}
			if !rs.trimmable {
				globalStableBlocked[d] = struct{}{}
			}
		}
		if removed > 0 {
			logInfo("Cross-policy dedup removed %d duplicate domain(s) from '%s' (priority %d)",
				removed, rs.policy.Name, rs.priority)
		}
	}

	// Pass 2b: Scoped/restricted domain block policies
	for _, idx := range order {
		rs := &rawSets[idx]
		if rs.policy.resolvedType() != "DOMAIN" || rs.policy.resolvedAction() == "allow" || !rs.policy.isScoped(cfg) {
			continue
		}
		idKey := rs.policy.effectiveIdentity(cfg)
		peerStable := scopedStableBlocked[idKey]
		if peerStable == nil {
			peerStable = make(map[string]struct{})
			scopedStableBlocked[idKey] = peerStable
		}
		peerAll := scopedAllBlocked[idKey]
		if peerAll == nil {
			peerAll = make(map[string]struct{})
			scopedAllBlocked[idKey] = peerAll
		}

		globalLookup := globalStableBlocked
		peerLookup := peerStable
		if rs.trimmable {
			globalLookup = globalAllBlocked
			peerLookup = peerAll
		}

		removed := 0
		for d := range rs.domains {
			if hasSuffixDomain(d, globalLookup) || hasSuffixDomain(d, peerLookup) {
				delete(rs.domains, d)
				removed++
			}
		}
		dedupCounts[idx] = removed
		for d := range rs.domains {
			peerAll[d] = struct{}{}
			if !rs.trimmable {
				peerStable[d] = struct{}{}
			}
		}
		if removed > 0 {
			logInfo("Cross-policy dedup removed %d duplicate domain(s) from scoped policy '%s' (priority %d)",
				removed, rs.policy.Name, rs.priority)
		}
	}

	// Step 3: Materialize rankedEntry slices sorted by (Rank asc, Value asc)
	out := make([]compiledPolicy, len(order))
	for outIdx, idx := range order {
		rs := rawSets[idx]
		if rs.policy.resolvedType() == "IP" {
			entries := make([]rankedEntry, len(rs.ips))
			for j, cidr := range rs.ips {
				entries[j] = rankedEntry{Value: cidr, Rank: 0}
			}
			out[outIdx] = compiledPolicy{
				Policy:   rs.policy,
				Priority: rs.priority,
				Entries:  entries,
				RawCount: rs.rawCount,
			}
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
			Policy:       rs.policy,
			Priority:     rs.priority,
			Trimmable:    rs.trimmable,
			Entries:      entries,
			RawCount:     rs.rawCount,
			DedupedCount: dedupCounts[idx],
			GuardedCount: rs.guardedCount,
		}
	}

	return out, guardWarnings
}

func sumMinCapacity(compiled []compiledPolicy, maxListSize int) (int, int) {
	entries, minLists := 0, 0
	for _, cp := range compiled {
		entries += len(cp.Entries)
		minLists += divCeil(len(cp.Entries), maxListSize)
	}
	return entries, minLists
}

// trimByRank removes the least-popular (highest rank number) domains ONLY from
// trimmable policies (Porn -> Badware -> Malware) until entry and list limits are met.
func trimByRank(compiled []compiledPolicy, activeQuota, maxActiveLists, maxListSize int) []string {
	var warnings []string
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

	// Pass 1: Trim excess entries while protecting each trimmable policy's top 10k domains
	// Pass 2: If still over quota, allow trimming into the protected 10k core
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
			available := len(cp.Entries) - floor
			if available <= 0 {
				continue
			}
			toDrop := min(available, totalEntries-activeQuota)
			cp.Entries = cp.Entries[:len(cp.Entries)-toDrop]
			cp.TrimmedCount += toDrop
			totalEntries -= toDrop
		}
	}

	// Pass 3: If entries fit activeQuota but list rounding exceeds maxActiveLists,
	// trim the smallest partial tail chunks from trimmable policies to reclaim whole lists.
	_, minLists = sumMinCapacity(compiled, maxListSize)
	for minLists > maxActiveLists {
		bestIdx := -1
		bestDrop := math.MaxInt
		bestPrio := -1

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
				bestDrop = tail
				bestIdx = idx
				bestPrio = compiled[idx].Priority
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

	for i := range compiled {
		cp := &compiled[i]
		if cp.TrimmedCount > 0 {
			worstRankStr := "none"
			if n := len(cp.Entries); n > 0 {
				r := cp.Entries[n-1].Rank
				if r == unrankedRank {
					worstRankStr = "unranked"
				} else {
					worstRankStr = fmt.Sprintf("#%d", r)
				}
			}
			msg := fmt.Sprintf("Rank-trimmed %d low-popularity domains from '%s' (kept %d, worst kept rank: %s)",
				cp.TrimmedCount, cp.Policy.Name, len(cp.Entries), worstRankStr)
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
	avg := len(entries)/numBuckets + 16
	for i := range buckets {
		buckets[i] = make([]string, 0, min(avg, maxListSize))
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
				b := (start + step) % numBuckets
				if len(buckets[b]) < maxListSize {
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
		count := 0
		for _, l := range existingLists {
			if _, ok := parseChunkIndex(l.Name, cp.Policy.Prefix); ok {
				count++
			}
		}
		existingCounts[cp.Policy.Prefix] = count
	}

	targetSize := max((maxListSize*90)/100, 1)
	minFillSize := max((maxListSize*75)/100, 1)

	bucketCounts := make([]int, len(compiled))
	minBuckets := make([]int, len(compiled))
	totalBuckets := 0

	for i, cp := range compiled {
		n := len(cp.Entries)
		if n == 0 {
			continue
		}
		if n <= maxListSize {
			bucketCounts[i] = 1
			minBuckets[i] = 1
			totalBuckets++
			continue
		}

		minB := divCeil(n, maxListSize)
		targetB := divCeil(n, targetSize)
		maxStickyB := divCeil(n, minFillSize)
		minBuckets[i] = minB

		existingB := existingCounts[cp.Policy.Prefix]
		if existingB >= minB && existingB <= maxStickyB {
			bucketCounts[i] = existingB
		} else {
			bucketCounts[i] = targetB
		}
		totalBuckets += bucketCounts[i]
	}

	for totalBuckets > maxActiveLists {
		slackestIdx := -1
		lowestFill := math.MaxFloat64
		for i, cp := range compiled {
			if bucketCounts[i] > minBuckets[i] {
				fill := float64(len(cp.Entries)) / float64(bucketCounts[i])
				if fill < lowestFill {
					lowestFill = fill
					slackestIdx = i
				}
			}
		}
		if slackestIdx < 0 {
			break
		}
		saved := bucketCounts[slackestIdx] - minBuckets[slackestIdx]
		bucketCounts[slackestIdx] = minBuckets[slackestIdx]
		totalBuckets -= saved
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

// ensureSpamAllowPrecedence verifies that "Allow: Spam Exceptions" executes immediately
// before any spam-TLD block rule (lower numeric precedence in Cloudflare Gateway),
// while staying below higher-priority block rules (Malware, Bypass, Social, AdBlock).
func ensureSpamAllowPrecedence(
	cf *cloudflareAPI,
	spamTLDBlockNames map[string]struct{},
	existingRules []gatewayRule,
) []string {
	if len(spamTLDBlockNames) == 0 {
		return nil
	}

	allowIdx := slices.IndexFunc(existingRules, func(r gatewayRule) bool {
		return r.Name == spamAllowRuleName
	})
	if allowIdx < 0 {
		if cf.dryRun {
			logInfo("[DRY-RUN] '%s' not yet created; precedence will be positioned directly above spam-TLD rule on live run.", spamAllowRuleName)
		}
		return nil
	}

	allowPrec, hasAllowPrec := parseRulePrecedence(existingRules[allowIdx].Precedence)
	if !hasAllowPrec {
		return nil
	}

	var spamBlockIndices []int
	minSpamPrec := int64(math.MaxInt64)
	for i, r := range existingRules {
		if _, isSpamBlock := spamTLDBlockNames[r.Name]; isSpamBlock {
			if p, ok := parseRulePrecedence(r.Precedence); ok {
				spamBlockIndices = append(spamBlockIndices, i)
				if p < minSpamPrec {
					minSpamPrec = p
				}
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

	// Find largest DNS precedence strictly below minSpamPrec and overall max DNS precedence
	var prevPrec int64
	var maxDNSPrec int64
	usedPrecs := make(map[int64]struct{}, len(existingRules))
	for i, r := range existingRules {
		if !r.isDNSRule() {
			continue
		}
		p, ok := parseRulePrecedence(r.Precedence)
		if !ok {
			continue
		}
		if p > maxDNSPrec {
			maxDNSPrec = p
		}
		if i != allowIdx {
			usedPrecs[p] = struct{}{}
			if p < minSpamPrec && p > prevPrec {
				prevPrec = p
			}
		}
	}

	updateRulePrec := func(idx int, newPrec int64) error {
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

	var notices []string

	// Case 1: There is at least one free integer strictly between prevPrec and minSpamPrec
	if prevPrec+1 < minSpamPrec {
		targetPrec := prevPrec + (minSpamPrec-prevPrec)/2
		if _, taken := usedPrecs[targetPrec]; taken {
			for cand := minSpamPrec - 1; cand > prevPrec; cand-- {
				if _, used := usedPrecs[cand]; !used {
					targetPrec = cand
					break
				}
			}
		}
		if err := updateRulePrec(allowIdx, targetPrec); err != nil {
			logErr("Failed adjusting precedence of '%s' to %d: %v", spamAllowRuleName, targetPrec, err)
			notices = append(notices, fmt.Sprintf("Failed to reorder '%s' above spam-TLD rule: %v", spamAllowRuleName, err))
			return notices
		}
		msg := fmt.Sprintf("Adjusted rule precedence: moved '%s' from %d to %d (directly above spam-TLD rule at %d)",
			spamAllowRuleName, allowPrec, targetPrec, minSpamPrec)
		logInfo("%s", msg)
		notices = append(notices, msg)
		return notices
	}

	// Case 2: No integer gap above minSpamPrec; place Allow + Spam TLD cleanly at the bottom
	allowTarget := maxDNSPrec + 50
	if err := updateRulePrec(allowIdx, allowTarget); err != nil {
		logErr("Failed relocating '%s' to precedence %d: %v", spamAllowRuleName, allowTarget, err)
		notices = append(notices, fmt.Sprintf("Failed to relocate '%s' precedence: %v", spamAllowRuleName, err))
		return notices
	}
	for offset, idx := range spamBlockIndices {
		spamTarget := maxDNSPrec + 100 + int64(offset*10)
		if err := updateRulePrec(idx, spamTarget); err != nil {
			logErr("Failed relocating '%s' to precedence %d: %v", existingRules[idx].Name, spamTarget, err)
			notices = append(notices, fmt.Sprintf("Failed to relocate '%s' precedence: %v", existingRules[idx].Name, err))
			return notices
		}
	}

	msg := fmt.Sprintf("Adjusted rule precedence: placed '%s' (%d) directly above spam-TLD rule(s) (%d+)",
		spamAllowRuleName, allowTarget, maxDNSPrec+100)
	logInfo("%s", msg)
	notices = append(notices, msg)
	return notices
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

// ---------- Sync Operations & Metrics ----------

type policySyncStats struct {
	Name         string
	Prefix       string
	Type         string
	Priority     int
	Trimmable    bool
	Status       string // "synced", "preserved", "inactive"
	Entries      int
	Deduped      int
	Trimmed      int
	ListsTotal   int
	ListsCreated int
	ListsUpdated int
	ListsSkipped int
	RuleAction   string // "unchanged", "updated", "created", "deleted", "preserved"
}

type policySyncResult struct {
	ActiveIDs  []string
	SurplusIDs []string
	RuleNames  []string
	Stats      policySyncStats
}

func syncPolicyInPlace(
	cf *cloudflareAPI,
	cfg *appConfig,
	existingLists []gatewayList,
	existingRules *[]gatewayRule,
	cp compiledPolicy,
	tldExpr string,
) (policySyncResult, error) {
	policy := cp.Policy
	stats := policySyncStats{
		Name:       policy.Name,
		Prefix:     policy.Prefix,
		Type:       policy.resolvedType(),
		Priority:   cp.Priority,
		Trimmable:  cp.Trimmable,
		Status:     "synced",
		Entries:    len(cp.Entries),
		Deduped:    cp.DedupedCount,
		Trimmed:    cp.TrimmedCount,
		RuleAction: "unchanged",
	}

	if policy.Prefix == "" || policy.Name == "" {
		logWarn("Skipping malformed policy with empty prefix or name.")
		stats.Status = "inactive"
		return policySyncResult{Stats: stats}, nil
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
	slices.SortFunc(matched, func(a, b indexedList) int { return cmp.Compare(a.idx, b.idx) })

	chunks := cp.Chunks
	writeWorkers := min(cfg.MaxWorkers, 3)
	sem := make(chan struct{}, writeWorkers)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		chunkNone = iota
		chunkSkipped
		chunkUpdated
		chunkCreated
	)
	chunkIDs := make([]string, len(chunks))
	chunkOps := make([]int, len(chunks))
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
				chunkOps[idx] = chunkSkipped
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
				var op int
				if hasTarget {
					id = matched[idx].list.ID
					err = cf.updateList(ctx, id, name, currentChunk, desc)
					op = chunkUpdated
					if err == nil {
						logInfo("Updated %s (%d %s items)", name, len(currentChunk), strings.ToLower(policyType))
					}
				} else {
					id, err = cf.createList(ctx, name, currentChunk, policyType, desc)
					op = chunkCreated
					if err == nil {
						logInfo("Created %s (%d %s items)", name, len(currentChunk), strings.ToLower(policyType))
					}
				}

				if err == nil {
					chunkIDs[idx] = id
					chunkOps[idx] = op
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
		return policySyncResult{}, firstErr
	}

	activeIDs := make([]string, 0, len(chunkIDs))
	for i, id := range chunkIDs {
		if id != "" {
			activeIDs = append(activeIDs, id)
		}
		switch chunkOps[i] {
		case chunkSkipped:
			stats.ListsSkipped++
		case chunkUpdated:
			stats.ListsUpdated++
		case chunkCreated:
			stats.ListsCreated++
		}
	}
	stats.ListsTotal = len(activeIDs)

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
		stats.Status = "inactive"
		if ruleIdx >= 0 {
			rid := rules[ruleIdx].ID
			if err := cf.deleteRule(rid); err != nil {
				logErr("Failed deleting inactive rule %s: %v", policy.Name, err)
			} else {
				logInfo("Removed inactive firewall rule: %s", policy.Name)
				*existingRules = slices.Delete(rules, ruleIdx, ruleIdx+1)
				stats.RuleAction = "deleted"
			}
		}
		return policySyncResult{ActiveIDs: activeIDs, SurplusIDs: surplusIDs, Stats: stats}, nil
	}

	cond := policy.effectiveIdentity(cfg)
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
				return policySyncResult{}, err
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
			stats.RuleAction = "updated"
			logInfo("Updated firewall rule: %s (enabled=%t, block_page=%t, ip_categories=%t)",
				policy.Name, ruleEnabled, blockPage, ipCat)
		}
	} else {
		created, err := cf.createRule(payload)
		if err != nil {
			return policySyncResult{}, err
		}
		if created != nil {
			*existingRules = append(rules, *created)
		}
		stats.RuleAction = "created"
		logInfo("Created firewall rule: %s (enabled=%t, block_page=%t, ip_categories=%t)",
			policy.Name, ruleEnabled, blockPage, ipCat)
	}

	return policySyncResult{
		ActiveIDs:  activeIDs,
		SurplusIDs: surplusIDs,
		RuleNames:  []string{policy.Name},
		Stats:      stats,
	}, nil
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

func policyHasActiveRule(cp compiledPolicy, tldExpr string) bool {
	return len(cp.Chunks) > 0 || (tldExpr != "" && cp.Policy.UseSpamTLD) || compileCategoryExpression(cp.Policy) != ""
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
		expectedChunks[cp.Policy.Prefix] = len(cp.Chunks)
		if policyHasActiveRule(cp, tldExpr) {
			expectedRules[cp.Policy.Name] = struct{}{}
		}
	}

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
		slices.SortFunc(matched, func(a, b indexedList) int { return cmp.Compare(a.idx, b.idx) })
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

// ---------- GitHub Actions Step Summary ----------

type syncSummaryData struct {
	DryRun          bool
	Duration        time.Duration
	RelevanceStatus string
	RelevanceCount  int
	FeedsOK         int
	FailedFeeds     []string
	TotalItems      int
	TotalQuota      int
	ManagedLists    int
	UnmanagedLists  int
	PolicyStats     []policySyncStats
	Warnings        []string
}

func writeStepSummary(data syncSummaryData) {
	summaryPath := strings.TrimSpace(os.Getenv("GITHUB_STEP_SUMMARY"))
	if summaryPath == "" {
		return
	}

	totalCreated, totalUpdated, totalSkipped := 0, 0, 0
	for _, ps := range data.PolicyStats {
		totalCreated += ps.ListsCreated
		totalUpdated += ps.ListsUpdated
		totalSkipped += ps.ListsSkipped
	}
	totalListOps := totalCreated + totalUpdated + totalSkipped
	cacheHitPct := 100.0
	if totalListOps > 0 {
		cacheHitPct = float64(totalSkipped) * 100.0 / float64(totalListOps)
	}
	itemPct := float64(data.TotalItems) * 100.0 / float64(max(data.TotalQuota, 1))
	usedLists := data.ManagedLists + data.UnmanagedLists
	listPct := float64(usedLists) * 100.0 / float64(maxCloudflareLists)

	var sb strings.Builder
	title := "Cloudflare Gateway Sync Summary"
	if data.DryRun {
		title += " (DRY-RUN)"
	}
	fmt.Fprintf(&sb, "## %s\n\n", title)
	fmt.Fprintf(&sb, "| Metric | Value |\n| :--- | :--- |\n")
	fmt.Fprintf(&sb, "| **Duration** | `%.2fs` |\n", data.Duration.Seconds())
	fmt.Fprintf(&sb, "| **Relevance Cache** | `%s` (%d root domains) |\n", data.RelevanceStatus, data.RelevanceCount)
	fmt.Fprintf(&sb, "| **Item Quota** | `%d / %d` (%.1f%%) |\n", data.TotalItems, data.TotalQuota, itemPct)
	fmt.Fprintf(&sb, "| **List Quota** | `%d / %d` (%.1f%% — %d managed, %d unmanaged) |\n",
		usedLists, maxCloudflareLists, listPct, data.ManagedLists, data.UnmanagedLists)
	fmt.Fprintf(&sb, "| **List Writes** | `%d` created, `%d` updated, `%d` unchanged (%.1f%% skipped) |\n",
		totalCreated, totalUpdated, totalSkipped, cacheHitPct)
	fmt.Fprintf(&sb, "| **Upstream Feeds** | `%d` ok, `%d` failed |\n\n", data.FeedsOK, len(data.FailedFeeds))

	fmt.Fprintf(&sb, "### Policies\n\n")
	fmt.Fprintf(&sb, "| Policy | Prio | Type | Mode | Status | Entries | Deduped | Trimmed | Lists (C/U/S) | Rule |\n")
	fmt.Fprintf(&sb, "| :--- | :---: | :---: | :---: | :---: | ---: | ---: | ---: | :---: | :---: |\n")
	for _, ps := range data.PolicyStats {
		mode := "protected"
		if ps.Trimmable {
			mode = "trimmable"
		}
		fmt.Fprintf(&sb, "| %s | %d | %s | `%s` | `%s` | %d | %d | %d | %d (%d/%d/%d) | `%s` |\n",
			ps.Name, ps.Priority, ps.Type, mode, ps.Status,
			ps.Entries, ps.Deduped, ps.Trimmed,
			ps.ListsTotal, ps.ListsCreated, ps.ListsUpdated, ps.ListsSkipped,
			ps.RuleAction,
		)
	}
	sb.WriteString("\n")

	if len(data.FailedFeeds) > 0 || len(data.Warnings) > 0 {
		sb.WriteString("### Warnings & Notices\n\n")
		for _, f := range data.FailedFeeds {
			fmt.Fprintf(&sb, "- **Upstream feed failed (preserved live state):** `%s`\n", f)
		}
		for _, w := range data.Warnings {
			fmt.Fprintf(&sb, "- %s\n", w)
		}
		sb.WriteString("\n")
	}

	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		logWarn("Could not write GITHUB_STEP_SUMMARY (%s): %v", summaryPath, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(sb.String()); err != nil {
		logWarn("Failed writing GITHUB_STEP_SUMMARY: %v", err)
	}
}

// ---------- Main Orchestration ----------

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
	spamTLDBlockNames := make(map[string]struct{})
	useSpamTLDAny := false
	for _, k := range policyKeys {
		p := cfg.Raw.Policies[k]
		if p.UseSpamTLD {
			useSpamTLDAny = true
			if p.resolvedAction() != "allow" && p.Name != "" {
				spamTLDBlockNames[p.Name] = struct{}{}
			}
		}
		allPolicies = append(allPolicies, p)
	}

	domainSources := parseSources(cfg.Raw.Sources, false)
	ipSources := parseSources(cfg.Raw.IPSources, true)

	if useSpamTLDAny && cfg.Raw.SpamAllowSource != nil && cfg.Raw.SpamAllowSource.Name != "" {
		sa := cfg.Raw.SpamAllowSource
		allPolicies = append(allPolicies, policyConfig{
			Prefix:  "L_AllowSpam",
			Name:    spamAllowRuleName,
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
	relevanceCount := 0
	if needsRelevance {
		relSet, relevanceStatus, err = resolveRelevanceDataset(feedClient, cfg)
		if err != nil {
			return err
		}
		relevanceCount = relSet.len()
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
			kept, err := fetchFeedSource(feedClient, spec, relSet)
			if err == nil && len(kept) == 0 {
				err = fmt.Errorf("feed '%s' returned 0 valid domains", spec.Name)
			}
			outcomes[i] = feedOutcome{
				name: spec.Name,
				feed: fetchedFeed{Domains: kept},
				err:  err,
			}
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
			outcomes[idx] = feedOutcome{
				name: spec.Name,
				feed: fetchedFeed{IsIP: true, IPs: nets},
				err:  err,
			}
		}(idx, spec)
	}
	wg.Wait()

	relSet = nil
	runtime.GC()

	fetched := make(map[string]fetchedFeed, totalSources)
	failedFeeds := make(map[string]struct{})
	var failedFeedList []string
	for _, o := range outcomes {
		if o.err != nil {
			logErr("Upstream feed '%s' failed: %v. Policies using it will be preserved as-is.", o.name, o.err)
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
		preservedItemsCount += pItems
		preservedStats = append(preservedStats, policySyncStats{
			Name:       p.Name,
			Prefix:     p.Prefix,
			Type:       p.resolvedType(),
			Priority:   p.resolvedPriority(cfg),
			Trimmable:  p.isTrimmable(),
			Status:     "preserved",
			Entries:    pItems,
			ListsTotal: pLists,
			RuleAction: "preserved",
		})
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

	var summaryWarnings []string

	compileAndFit := func(pols []policyConfig, elists []gatewayList) ([]compiledPolicy, int, int, error) {
		compiled, guardWarns := buildPolicySets(cfg, pols, fetched, spamTLDs, hasActiveSpamTLD)
		if len(guardWarns) > 0 {
			summaryWarnings = append(summaryWarnings, fmt.Sprintf("Safety floor protected %d root domain(s): %s",
				len(guardWarns), strings.Join(guardWarns, ", ")))
		}

		// Primary capacity strategy: surgical rank-aware trimming (Porn -> Badware -> Malware)
		trimWarns := trimByRank(compiled, activeQuota, maxActiveLists, cfg.MaxListSize)
		summaryWarnings = append(summaryWarnings, trimWarns...)
		entries, minLists := sumMinCapacity(compiled, cfg.MaxListSize)

		// Emergency fallback tiers only shed Porn/TIF feeds; static safety lists are never touched
		if entries > activeQuota || minLists > maxActiveLists {
			msg := fmt.Sprintf("Capacity still exceeded after rank trimming (%d/%d entries, %d/%d min lists); shedding OISD NSFW...",
				entries, activeQuota, minLists, maxActiveLists)
			logWarn("%s", msg)
			summaryWarnings = append(summaryWarnings, msg)
			filterPolicyIncludes(pols, func(inc string) bool {
				l := strings.ToLower(inc)
				return !(strings.Contains(l, "oisd") && strings.Contains(l, "nsfw"))
			})
			compiled, _ = buildPolicySets(cfg, pols, fetched, spamTLDs, hasActiveSpamTLD)
			trimByRank(compiled, activeQuota, maxActiveLists, cfg.MaxListSize)
			entries, minLists = sumMinCapacity(compiled, cfg.MaxListSize)
		}

		if entries > activeQuota || minLists > maxActiveLists {
			msg := fmt.Sprintf("Capacity still exceeded (%d/%d entries, %d/%d min lists); shedding TIF IPs...",
				entries, activeQuota, minLists, maxActiveLists)
			logWarn("%s", msg)
			summaryWarnings = append(summaryWarnings, msg)
			filterPolicyIncludes(pols, func(inc string) bool {
				l := strings.ToLower(inc)
				return !(strings.Contains(l, "tif") && strings.Contains(l, "ip"))
			})
			compiled, _ = buildPolicySets(cfg, pols, fetched, spamTLDs, hasActiveSpamTLD)
			trimByRank(compiled, activeQuota, maxActiveLists, cfg.MaxListSize)
			entries, minLists = sumMinCapacity(compiled, cfg.MaxListSize)
		}

		if entries > activeQuota || minLists > maxActiveLists {
			msg := fmt.Sprintf("Capacity still exceeded (%d/%d entries, %d/%d min lists); shedding TIF domain feeds...",
				entries, activeQuota, minLists, maxActiveLists)
			logWarn("%s", msg)
			summaryWarnings = append(summaryWarnings, msg)
			filterPolicyIncludes(pols, func(inc string) bool {
				return !strings.Contains(strings.ToLower(inc), "tif")
			})
			compiled, _ = buildPolicySets(cfg, pols, fetched, spamTLDs, hasActiveSpamTLD)
			trimByRank(compiled, activeQuota, maxActiveLists, cfg.MaxListSize)
			entries, minLists = sumMinCapacity(compiled, cfg.MaxListSize)
		}

		if entries > activeQuota || minLists > maxActiveLists {
			return nil, 0, 0, fmt.Errorf("capacity exceeded after all trimming and fallback tiers (Active Entries: %d/%d, Min Lists: %d/%d)",
				entries, activeQuota, minLists, maxActiveLists)
		}

		totalChunks := assignHashBuckets(compiled, elists, cfg.MaxListSize, maxActiveLists)
		return compiled, entries, totalChunks, nil
	}

	compiled, activeEntries, totalChunks, err := compileAndFit(activePolicies, existingLists)
	if err != nil {
		return err
	}

	logInfo("Cloudflare lists: %d total (%d unmanaged, %d preserved, %d live items). Syncing %d hash-bucketed list(s)...",
		len(existingLists), unmanagedListsCount, len(preservedListIDs), currentManagedItems, totalChunks)

	standaloneRules := syncStandalonePolicies(cf, cfg, existingRules)

	reclaimSnapshots, reclaimedIDs, err := reclaimStaleResources(
		cf, cfg, compiled, tldExpr, preservedListIDs, preservedRuleNames, &existingLists, &existingRules,
	)
	if err != nil {
		return err
	}

	initTracking := func() ([]string, []string, []string, []policySyncStats) {
		actIDs := make([]string, 0, len(preservedListIDs)+totalChunks)
		for id := range preservedListIDs {
			actIDs = append(actIDs, id)
		}
		actRules := make([]string, 0, len(standaloneRules)+len(preservedRuleNames)+len(compiled))
		actRules = append(actRules, standaloneRules...)
		for name := range preservedRuleNames {
			actRules = append(actRules, name)
		}
		stats := make([]policySyncStats, 0, len(compiled)+len(preservedStats))
		return actIDs, nil, actRules, stats
	}

	allActiveIDs, allSurplusIDs, allActiveRules, policyStats := initTracking()

	runSync := func(sets []compiledPolicy, elists []gatewayList, erules *[]gatewayRule) error {
		for _, cp := range sets {
			expr := ""
			if cp.Policy.UseSpamTLD {
				expr = tldExpr
			}
			res, syncErr := syncPolicyInPlace(cf, cfg, elists, erules, cp, expr)
			if syncErr != nil {
				return syncErr
			}
			allActiveIDs = append(allActiveIDs, res.ActiveIDs...)
			allSurplusIDs = append(allSurplusIDs, res.SurplusIDs...)
			allActiveRules = append(allActiveRules, res.RuleNames...)
			policyStats = append(policyStats, res.Stats)
		}
		return nil
	}

	if syncErr := runSync(compiled, existingLists, &existingRules); syncErr != nil {
		errStr := syncErr.Error()
		if strings.Contains(errStr, "Maximum number of lists reached") || strings.Contains(errStr, "2017") {
			logErr("Cloudflare list limit (300) hit during sync! Forcing emergency list reclamation and rebuild...")
			summaryWarnings = append(summaryWarnings, "Emergency 300-list limit recovery triggered during sync.")

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
				existingLists, err = cf.getLists()
				if err != nil {
					return err
				}
				existingRules, err = cf.getRules()
				if err != nil {
					return err
				}

				compiled, activeEntries, totalChunks, err = compileAndFit(activePolicies, existingLists)
				if err != nil {
					return err
				}

				allActiveIDs, allSurplusIDs, allActiveRules, policyStats = initTracking()
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

	// Ensure Allow: Spam Exceptions sits directly above HaGeZi Spam TLD
	precNotices := ensureSpamAllowPrecedence(cf, spamTLDBlockNames, existingRules)
	summaryWarnings = append(summaryWarnings, precNotices...)

	policyStats = append(policyStats, preservedStats...)
	slices.SortFunc(policyStats, func(a, b policySyncStats) int {
		if c := cmp.Compare(a.Priority, b.Priority); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	totalCreated, totalUpdated, totalSkipped := 0, 0, 0
	for _, ps := range policyStats {
		totalCreated += ps.ListsCreated
		totalUpdated += ps.ListsUpdated
		totalSkipped += ps.ListsSkipped
	}

	elapsed := time.Since(start)
	totalLiveEntries := activeEntries + preservedItemsCount
	logInfo("Sync finished in %.2fs | relevance=%s | lists=%d (C:%d U:%d S:%d) | items=%d/%d | feeds_ok=%d failed=%d",
		elapsed.Seconds(),
		relevanceStatus,
		len(allActiveIDs),
		totalCreated,
		totalUpdated,
		totalSkipped,
		totalLiveEntries,
		cfg.TotalQuota,
		len(fetched),
		len(failedFeedList),
	)

	writeStepSummary(syncSummaryData{
		DryRun:          cfg.DryRun,
		Duration:        elapsed,
		RelevanceStatus: relevanceStatus,
		RelevanceCount:  relevanceCount,
		FeedsOK:         len(fetched),
		FailedFeeds:     failedFeedList,
		TotalItems:      totalLiveEntries,
		TotalQuota:      cfg.TotalQuota,
		ManagedLists:    len(allActiveIDs),
		UnmanagedLists:  unmanagedListsCount,
		PolicyStats:     policyStats,
		Warnings:        summaryWarnings,
	})

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
