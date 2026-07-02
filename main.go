package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	void* call;
	void* free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginID                     = "cpa-policy-hub"
	legacyPluginID               = "api-key-token-limiter"
	pluginDisplayName            = "CPA Policy Hub"
	pluginVersion                = "0.1.0"
	interfaceOverrideHeader      = "X-CLIProxy-Force-Interface"
	interfaceOverrideMatchHeader = "X-CLIProxy-Force-Interface-Match"
	maxManagementBodyBytes       = 4 << 20
	maxAuthModelBodyBytes        = 1 << 20
)

var currentLimiter = &limiter{
	cfg: pluginConfig{
		StoragePath: "cpa-policy-hub-state.json",
	},
	configuredKeys: map[string]keyRule{},
	state: persistedState{
		Keys:  map[string]keyRule{},
		Usage: map[string]*usageCounter{},
	},
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type registration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  capabilities       `json:"capabilities"`
}

type capabilities struct {
	FrontendAuthProvider          bool `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive bool `json:"frontend_auth_provider_exclusive"`
	RequestInterceptor            bool `json:"request_interceptor"`
	ResponseInterceptor           bool `json:"response_interceptor"`
	UsagePlugin                   bool `json:"usage_plugin"`
	ManagementAPI                 bool `json:"management_api"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

type pluginConfig struct {
	Enabled                      bool                   `yaml:"enabled" json:"enabled"`
	Priority                     int                    `yaml:"priority" json:"priority"`
	TrafficEnabled               bool                   `yaml:"traffic_enabled" json:"traffic_enabled"`
	Exclusive                    bool                   `yaml:"exclusive" json:"exclusive"`
	StoragePath                  string                 `yaml:"storage_path" json:"storage_path"`
	ConfigPath                   string                 `yaml:"config_path" json:"config_path"`
	ManageConfigAPIKeys          bool                   `yaml:"manage_config_api_keys" json:"manage_config_api_keys"`
	FailClosed                   bool                   `yaml:"fail_closed" json:"fail_closed"`
	DryRun                       bool                   `yaml:"dry_run" json:"dry_run"`
	ExposeLimitHeaders           bool                   `yaml:"expose_limit_headers" json:"expose_limit_headers"`
	DefaultDailyTokenLimit       int64                  `yaml:"default_daily_token_limit" json:"default_daily_token_limit"`
	DefaultMonthlyTokenLimit     int64                  `yaml:"default_monthly_token_limit" json:"default_monthly_token_limit"`
	DefaultTotalTokenLimit       int64                  `yaml:"default_total_token_limit" json:"default_total_token_limit"`
	DefaultRequestLimitPerMinute int                    `yaml:"default_request_limit_per_minute" json:"default_request_limit_per_minute"`
	DefaultAllowedModels         []string               `yaml:"default_allowed_models" json:"default_allowed_models"`
	Auth                         authConfig             `yaml:"auth" json:"auth"`
	Pricing                      []pricingRule          `yaml:"pricing" json:"pricing"`
	Policies                     []policyRule           `yaml:"policies" json:"policies"`
	EndpointOverrides            []endpointOverrideRule `yaml:"endpoint_overrides" json:"endpoint_overrides"`
	Keys                         []keyRule              `yaml:"keys" json:"keys"`
}

type hostConfigAPIKeys struct {
	APIKeys      []string `yaml:"api-keys"`
	APIKeysAlias []string `yaml:"api_keys"`
}

type authConfig struct {
	Exclusive bool      `yaml:"exclusive" json:"exclusive"`
	Keys      []keyRule `yaml:"keys" json:"keys"`
}

type policyRule struct {
	Name      string               `yaml:"name" json:"name,omitempty"`
	Deny      bool                 `yaml:"deny" json:"deny,omitempty"`
	Message   string               `yaml:"message" json:"message,omitempty"`
	Match     policyMatch          `yaml:"match" json:"match,omitempty"`
	Interface endpointOverrideRule `yaml:"interface" json:"interface,omitempty"`
	Quota     policyQuota          `yaml:"quota" json:"quota,omitempty"`
	Request   requestPolicyAction  `yaml:"request" json:"request,omitempty"`
	Response  responsePolicyAction `yaml:"response" json:"response,omitempty"`
	Metadata  map[string]any       `yaml:"metadata" json:"metadata,omitempty"`
}

type policyMatch struct {
	Keys            []string `yaml:"keys" json:"keys,omitempty"`
	Providers       []string `yaml:"providers" json:"providers,omitempty"`
	Models          []string `yaml:"models" json:"models,omitempty"`
	RequestedModels []string `yaml:"requested_models" json:"requested_models,omitempty"`
	SourceFormats   []string `yaml:"source_formats" json:"source_formats,omitempty"`
	ToFormats       []string `yaml:"to_formats" json:"to_formats,omitempty"`
	RequestPaths    []string `yaml:"request_paths" json:"request_paths,omitempty"`
}

type pricingRule struct {
	Model              string  `yaml:"model" json:"model"`
	InputPer1M         float64 `yaml:"input_per_1m" json:"input_per_1m,omitempty"`
	OutputPer1M        float64 `yaml:"output_per_1m" json:"output_per_1m,omitempty"`
	ReasoningPer1M     float64 `yaml:"reasoning_per_1m" json:"reasoning_per_1m,omitempty"`
	CachedInputPer1M   float64 `yaml:"cached_input_per_1m" json:"cached_input_per_1m,omitempty"`
	FlatRequestCost    float64 `yaml:"flat_request_cost" json:"flat_request_cost,omitempty"`
	Currency           string  `yaml:"currency" json:"currency,omitempty"`
	EstimatedInput     int64   `yaml:"estimated_input_tokens" json:"estimated_input_tokens,omitempty"`
	EstimatedOutput    int64   `yaml:"estimated_output_tokens" json:"estimated_output_tokens,omitempty"`
	EstimatedReasoning int64   `yaml:"estimated_reasoning_tokens" json:"estimated_reasoning_tokens,omitempty"`
}

type endpointOverrideRule struct {
	Name            string   `yaml:"name" json:"name,omitempty"`
	Keys            []string `yaml:"keys" json:"keys,omitempty"`
	Providers       []string `yaml:"providers" json:"providers,omitempty"`
	Models          []string `yaml:"models" json:"models,omitempty"`
	RequestedModels []string `yaml:"requested_models" json:"requested_models,omitempty"`
	SourceFormats   []string `yaml:"source_formats" json:"source_formats,omitempty"`
	ToFormats       []string `yaml:"to_formats" json:"to_formats,omitempty"`
	RequestPaths    []string `yaml:"request_paths" json:"request_paths,omitempty"`
	Interfaces      []string `yaml:"interfaces" json:"interfaces,omitempty"`
	ForceInterface  string   `yaml:"force_interface" json:"force_interface,omitempty"`
	Preserve        bool     `yaml:"preserve" json:"preserve"`
}

type requestPolicyAction struct {
	SetHeaders      map[string]string      `yaml:"set_headers" json:"set_headers,omitempty"`
	DeleteHeaders   []string               `yaml:"delete_headers" json:"delete_headers,omitempty"`
	SetJSON         map[string]any         `yaml:"set_json" json:"set_json,omitempty"`
	DeleteJSON      []string               `yaml:"delete_json" json:"delete_json,omitempty"`
	SetModel        string                 `yaml:"set_model" json:"set_model,omitempty"`
	SetServiceTier  string                 `yaml:"set_service_tier" json:"set_service_tier,omitempty"`
	MaxTokens       *intClamp              `yaml:"max_tokens" json:"max_tokens,omitempty"`
	Temperature     *floatClamp            `yaml:"temperature" json:"temperature,omitempty"`
	ReasoningEffort reasoningEffortPolicy  `yaml:"reasoning_effort" json:"reasoning_effort,omitempty"`
	Metadata        map[string]interface{} `yaml:"metadata" json:"metadata,omitempty"`
}

var protectedRequestHeaders = map[string]struct{}{
	"authorization":     {},
	"proxy-authorization": {},
	"cookie":            {},
	"set-cookie":        {},
	"x-api-key":         {},
	"x-goog-api-key":    {},
	"x-cli-key":         {},
	"host":              {},
}

var protectedResponseHeaders = map[string]struct{}{
	"set-cookie": {},
	"server":     {},
}

type timeWindowRule struct {
	Name      string   `yaml:"name" json:"name,omitempty"`
	Timezone  string   `yaml:"timezone" json:"timezone,omitempty"`
	Days      []string `yaml:"days" json:"days,omitempty"`
	Start     string   `yaml:"start" json:"start,omitempty"`
	End       string   `yaml:"end" json:"end,omitempty"`
	Deny      bool     `yaml:"deny" json:"deny,omitempty"`
	Message   string   `yaml:"message" json:"message,omitempty"`
}

type errorResponseRule struct {
	Name            string            `yaml:"name" json:"name,omitempty"`
	StatusCode      int               `yaml:"status_code" json:"status_code,omitempty"`
	Message         string            `yaml:"message" json:"message,omitempty"`
	Body            string            `yaml:"body" json:"body,omitempty"`
	JSON            map[string]any    `yaml:"json" json:"json,omitempty"`
	SetHeaders      map[string]string `yaml:"set_headers" json:"set_headers,omitempty"`
	HideUpstream    bool              `yaml:"hide_upstream" json:"hide_upstream,omitempty"`
	UpstreamStatuses []int            `yaml:"upstream_statuses" json:"upstream_statuses,omitempty"`
}

type responsePolicyAction struct {
	SetHeaders    map[string]string      `yaml:"set_headers" json:"set_headers,omitempty"`
	DeleteHeaders []string               `yaml:"delete_headers" json:"delete_headers,omitempty"`
	SetJSON       map[string]any         `yaml:"set_json" json:"set_json,omitempty"`
	DeleteJSON    []string               `yaml:"delete_json" json:"delete_json,omitempty"`
	Metadata      map[string]interface{} `yaml:"metadata" json:"metadata,omitempty"`
}

type intClamp struct {
	Min int64 `yaml:"min" json:"min,omitempty"`
	Max int64 `yaml:"max" json:"max,omitempty"`
}

type floatClamp struct {
	Min float64 `yaml:"min" json:"min,omitempty"`
	Max float64 `yaml:"max" json:"max,omitempty"`
}

type reasoningEffortPolicy struct {
	Deny    []string `yaml:"deny" json:"deny,omitempty"`
	Replace string   `yaml:"replace" json:"replace,omitempty"`
}

type policyQuota struct {
	Scope                  string  `yaml:"scope" json:"scope,omitempty"`
	DailyTokenLimit        int64   `yaml:"daily_token_limit" json:"daily_token_limit,omitempty"`
	MonthlyTokenLimit      int64   `yaml:"monthly_token_limit" json:"monthly_token_limit,omitempty"`
	TotalTokenLimit        int64   `yaml:"total_token_limit" json:"total_token_limit,omitempty"`
	RequestLimitPerMinute  int     `yaml:"request_limit_per_minute" json:"request_limit_per_minute,omitempty"`
	DailyRequestLimit      int64   `yaml:"daily_request_limit" json:"daily_request_limit,omitempty"`
	MonthlyRequestLimit    int64   `yaml:"monthly_request_limit" json:"monthly_request_limit,omitempty"`
	TotalRequestLimit      int64   `yaml:"total_request_limit" json:"total_request_limit,omitempty"`
	ConcurrencyLimit       int     `yaml:"concurrency_limit" json:"concurrency_limit,omitempty"`
	EstimatedTokensPerCall int64   `yaml:"estimated_tokens_per_call" json:"estimated_tokens_per_call,omitempty"`
	DailyCostLimit         float64 `yaml:"daily_cost_limit" json:"daily_cost_limit,omitempty"`
	MonthlyCostLimit       float64 `yaml:"monthly_cost_limit" json:"monthly_cost_limit,omitempty"`
	TotalCostLimit         float64 `yaml:"total_cost_limit" json:"total_cost_limit,omitempty"`
}

type keyRule struct {
	ID                    string                 `yaml:"id" json:"id"`
	Name                  string                 `yaml:"name" json:"name,omitempty"`
	Tenant                string                 `yaml:"tenant" json:"tenant,omitempty"`
	Plan                  string                 `yaml:"plan" json:"plan,omitempty"`
	Key                   string                 `yaml:"key" json:"key,omitempty"`
	KeyHash               string                 `yaml:"key_hash" json:"key_hash"`
	Disabled              bool                   `yaml:"disabled" json:"disabled"`
	ExpiresAt             string                 `yaml:"expires_at" json:"expires_at,omitempty"`
	DailyTokenLimit       int64                  `yaml:"daily_token_limit" json:"daily_token_limit"`
	MonthlyTokenLimit     int64                  `yaml:"monthly_token_limit" json:"monthly_token_limit"`
	TotalTokenLimit       int64                  `yaml:"total_token_limit" json:"total_token_limit"`
	HourlyTokenLimit      int64                  `yaml:"hourly_token_limit" json:"hourly_token_limit"`
	HourlyRequestLimit    int64                  `yaml:"hourly_request_limit" json:"hourly_request_limit"`
	RequestLimitPerMinute int                    `yaml:"request_limit_per_minute" json:"request_limit_per_minute"`
	AllowedModels         []string               `yaml:"allowed_models" json:"allowed_models,omitempty"`
	DeniedModels          []string               `yaml:"denied_models" json:"denied_models,omitempty"`
	AllowedProviders      []string               `yaml:"allowed_providers" json:"allowed_providers,omitempty"`
	DeniedProviders       []string               `yaml:"denied_providers" json:"denied_providers,omitempty"`
	TimeWindows           []timeWindowRule       `yaml:"time_windows" json:"time_windows,omitempty"`
	EndpointOverrides     []endpointOverrideRule `yaml:"endpoint_overrides" json:"endpoint_overrides,omitempty"`
	Request               requestPolicyAction    `yaml:"request" json:"request,omitempty"`
	Response              responsePolicyAction   `yaml:"response" json:"response,omitempty"`
	ErrorResponse         errorResponseRule      `yaml:"error_response" json:"error_response,omitempty"`
	Metadata              map[string]string      `yaml:"metadata" json:"metadata,omitempty"`
	Source                string                 `yaml:"-" json:"source,omitempty"`
}

type persistedState struct {
	Keys      map[string]keyRule       `json:"keys"`
	Usage     map[string]*usageCounter `json:"usage"`
	Events    []usageEvent             `json:"events,omitempty"`
	PolicyLog []policyEvent            `json:"policy_log,omitempty"`
	Policies  map[string]*usageCounter `json:"policies,omitempty"`
	Active    map[string]int           `json:"active,omitempty"`
	UpdatedAt time.Time                `json:"updated_at"`
}

type usageCounter struct {
	TotalTokens      int64              `json:"total_tokens"`
	InputTokens      int64              `json:"input_tokens"`
	OutputTokens     int64              `json:"output_tokens"`
	ReasoningTokens  int64              `json:"reasoning_tokens"`
	CachedTokens     int64              `json:"cached_tokens"`
	Requests         int64              `json:"requests"`
	FailedRequests   int64              `json:"failed_requests"`
	TotalCost        float64            `json:"total_cost,omitempty"`
	MaxActive        int                `json:"max_active,omitempty"`
	DailyCost        map[string]float64 `json:"daily_cost,omitempty"`
	MonthlyCost      map[string]float64 `json:"monthly_cost,omitempty"`
	HourlyTokens     map[string]int64   `json:"hourly_tokens,omitempty"`
	HourlyRequests   map[string]int64   `json:"hourly_requests,omitempty"`
	DailyTokens      map[string]int64   `json:"daily_tokens"`
	MonthlyTokens    map[string]int64   `json:"monthly_tokens"`
	RequestsByMinute map[string]int     `json:"requests_by_minute"`
	Models           map[string]int64   `json:"models"`
	LastUsedAt       time.Time          `json:"last_used_at,omitempty"`
}

func (u *usageCounter) clone() *usageCounter {
	if u == nil {
		return nil
	}
	cloned := *u
	cloned.DailyCost = cloneFloatMap(u.DailyCost)
	cloned.MonthlyCost = cloneFloatMap(u.MonthlyCost)
	cloned.HourlyTokens = cloneInt64Map(u.HourlyTokens)
	cloned.HourlyRequests = cloneInt64Map(u.HourlyRequests)
	cloned.DailyTokens = cloneInt64Map(u.DailyTokens)
	cloned.MonthlyTokens = cloneInt64Map(u.MonthlyTokens)
	cloned.RequestsByMinute = cloneIntMap(u.RequestsByMinute)
	cloned.Models = cloneInt64Map(u.Models)
	return &cloned
}

type usageEvent struct {
	At           time.Time `json:"at"`
	KeyID        string    `json:"key_id"`
	Provider     string    `json:"provider,omitempty"`
	Model        string    `json:"model,omitempty"`
	TotalTokens  int64     `json:"total_tokens"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	Failed       bool      `json:"failed"`
}

type policyEvent struct {
	At          time.Time `json:"at"`
	Policy      string    `json:"policy"`
	Action      string    `json:"action"`
	KeyID       string    `json:"key_id,omitempty"`
	Provider    string    `json:"provider,omitempty"`
	Model       string    `json:"model,omitempty"`
	RequestPath string    `json:"request_path,omitempty"`
	DryRun      bool      `json:"dry_run,omitempty"`
	Message     string    `json:"message,omitempty"`
}

type limiter struct {
	mu              sync.Mutex
	cfg             pluginConfig
	configuredKeys  map[string]keyRule
	state           persistedState
	configLoadError string
}

type managementRequest struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type keyListItem struct {
	keyRule
	Usage *usageCounter `json:"usage,omitempty"`
}

type createKeyResponse struct {
	Key    keyRule `json:"key"`
	APIKey string  `json:"api_key,omitempty"`
}

type resetRequest struct {
	Target string `json:"target"`
	ID     string `json:"id,omitempty"`
}

type importStateRequest struct {
	Replace bool           `json:"replace"`
	State   persistedState `json:"state"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = len
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodFrontendAuthIdentifier:
		return okEnvelope(identifierResponse{Identifier: pluginID})
	case pluginabi.MethodFrontendAuthAuthenticate:
		return authenticate(request)
	case pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter:
		return interceptRequest(request)
	case pluginabi.MethodResponseInterceptAfter:
		return interceptResponse(request)
	case pluginabi.MethodUsageHandle:
		return handleUsage(request)
	case pluginabi.MethodManagementRegister:
		return registerManagement()
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	cfg := pluginConfig{
		StoragePath:          "cpa-policy-hub-state.json",
		DefaultAllowedModels: []string{"*"},
	}
	var req lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	normalizePolicyConfigAliases(&cfg)
	if strings.TrimSpace(cfg.StoragePath) == "" {
		cfg.StoragePath = "cpa-policy-hub-state.json"
	}
	configLoadError := ""
	if cfg.ManageConfigAPIKeys {
		hostKeys, errLoadKeys := loadConfigAPIKeys(cfg.ConfigPath)
		if errLoadKeys != nil {
			configLoadError = errLoadKeys.Error()
		} else {
			cfg.Keys = append(configAPIKeyRules(hostKeys), cfg.Keys...)
		}
	}
	configuredKeys := make(map[string]keyRule, len(cfg.Keys))
	for _, rule := range cfg.Keys {
		normalized, ok := normalizeKeyRule(rule, cfg, "config")
		if !ok {
			continue
		}
		configuredKeys[normalized.ID] = normalized
	}
	state, errLoad := loadState(cfg.StoragePath)
	if errLoad != nil && cfg.FailClosed {
		return errLoad
	}
	if state.Keys == nil {
		state.Keys = map[string]keyRule{}
	}
	if state.Usage == nil {
		state.Usage = map[string]*usageCounter{}
	}
	if state.PolicyLog == nil {
		state.PolicyLog = []policyEvent{}
	}
	if state.Policies == nil {
		state.Policies = map[string]*usageCounter{}
	}
	if state.Active == nil {
		state.Active = map[string]int{}
	}
	currentLimiter.mu.Lock()
	currentLimiter.cfg = cfg
	currentLimiter.configLoadError = configLoadError
	currentLimiter.configuredKeys = configuredKeys
	currentLimiter.state = state
	currentLimiter.mu.Unlock()
	return nil
}

func normalizePolicyConfigAliases(cfg *pluginConfig) {
	if cfg == nil {
		return
	}
	if cfg.Auth.Exclusive {
		cfg.Exclusive = true
	}
	if len(cfg.Auth.Keys) > 0 {
		cfg.Keys = append(cfg.Keys, cfg.Auth.Keys...)
	}
	for _, policy := range cfg.Policies {
		if override, ok := endpointOverrideFromPolicy(policy); ok {
			cfg.EndpointOverrides = append(cfg.EndpointOverrides, override)
		}
	}
}

func loadConfigAPIKeys(configPath string) ([]string, error) {
	path := strings.TrimSpace(configPath)
	paths := []string{path}
	if path == "" {
		paths = []string{"config.yaml", "./config.yaml", "/CLIProxyAPI/config.yaml", "/home/docker/CLIProxyAPI/config.yaml"}
	}
	var raw []byte
	var errRead error
	for _, candidate := range paths {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		raw, errRead = os.ReadFile(candidate)
		if errRead == nil {
			break
		}
	}
	if errRead != nil {
		return nil, errRead
	}
	var cfg hostConfigAPIKeys
	if errUnmarshal := yaml.Unmarshal(raw, &cfg); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	keys := append([]string(nil), cfg.APIKeys...)
	keys = append(keys, cfg.APIKeysAlias...)
	return uniqueNonEmptyStrings(keys), nil
}

func configAPIKeyRules(keys []string) []keyRule {
	rules := make([]keyRule, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		hash := hashAPIKey(key)
		id := "config_api_key_" + strings.TrimPrefix(hash, "sha256:")[:12]
		rules = append(rules, keyRule{ID: id, Name: "CPA config api-key", KeyHash: hash})
	}
	return rules
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func endpointOverrideFromPolicy(policy policyRule) (endpointOverrideRule, bool) {
	policy.Name = strings.TrimSpace(policy.Name)
	override := policy.Interface
	override.Name = firstNonEmpty(override.Name, policy.Name)
	override.Keys = appendIfEmpty(override.Keys, policy.Match.Keys)
	override.Providers = appendIfEmpty(override.Providers, policy.Match.Providers)
	override.Models = appendIfEmpty(override.Models, policy.Match.Models)
	override.RequestedModels = appendIfEmpty(override.RequestedModels, policy.Match.RequestedModels)
	override.SourceFormats = appendIfEmpty(override.SourceFormats, policy.Match.SourceFormats)
	override.ToFormats = appendIfEmpty(override.ToFormats, policy.Match.ToFormats)
	override.RequestPaths = appendIfEmpty(override.RequestPaths, policy.Match.RequestPaths)
	if strings.TrimSpace(override.ForceInterface) == "" && len(override.Interfaces) == 0 && !override.Preserve {
		return endpointOverrideRule{}, false
	}
	return override, true
}

func appendIfEmpty(current []string, fallback []string) []string {
	if len(current) > 0 || len(fallback) == 0 {
		return current
	}
	return append([]string(nil), fallback...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func pluginRegistration() registration {
	currentLimiter.mu.Lock()
	runtimeCapabilities := currentLimiter.runtimeCapabilitiesLocked()
	currentLimiter.mu.Unlock()
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginDisplayName,
			Version:          pluginVersion,
			Author:           "MingWant",
			GitHubRepository: "https://github.com/MingWant/cpa-policy-hub",
			Logo:             "",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "exclusive", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Use this plugin as the exclusive frontend API key authenticator."},
				{Name: "traffic_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Explicitly allow this plugin to participate in normal CPA traffic. Leave false for management-only mode."},
				{Name: "storage_path", Type: pluginapi.ConfigFieldTypeString, Description: "JSON state file for managed keys, counters, and recent usage events."},
				{Name: "config_path", Type: pluginapi.ConfigFieldTypeString, Description: "Optional CPA config.yaml path used when manage_config_api_keys is enabled."},
				{Name: "manage_config_api_keys", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Import top-level CPA config.yaml api-keys into Policy Hub and apply default limits."},
				{Name: "fail_closed", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Reject plugin startup when persistent state cannot be loaded."},
				{Name: "dry_run", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Record deny and mutation policy matches without enforcing deny or mutating requests/responses."},
				{Name: "expose_limit_headers", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Add basic limiter headers to successful responses."},
				{Name: "default_daily_token_limit", Type: pluginapi.ConfigFieldTypeInteger, Description: "Default daily token quota for keys without a per-key value. Zero means unlimited."},
				{Name: "default_monthly_token_limit", Type: pluginapi.ConfigFieldTypeInteger, Description: "Default monthly token quota for keys without a per-key value. Zero means unlimited."},
				{Name: "default_total_token_limit", Type: pluginapi.ConfigFieldTypeInteger, Description: "Default lifetime token quota for keys without a per-key value. Zero means unlimited."},
				{Name: "default_request_limit_per_minute", Type: pluginapi.ConfigFieldTypeInteger, Description: "Default request rate limit per minute. Zero means unlimited."},
				{Name: "default_allowed_models", Type: pluginapi.ConfigFieldTypeArray, Description: "Default allowed model list. Supports exact names, '*', prefix*, and *suffix patterns."},
				{Name: "auth", Type: pluginapi.ConfigFieldTypeObject, Description: "Policy Hub auth block. Supports auth.exclusive and auth.keys as aliases for exclusive and keys."},
				{Name: "policies", Type: pluginapi.ConfigFieldTypeArray, Description: "Policy rules. The initial policy engine maps policy match + interface blocks to conditional upstream interface overrides."},
				{Name: "endpoint_overrides", Type: pluginapi.ConfigFieldTypeArray, Description: "Global conditional upstream interface overrides. Target interfaces: passthrough, chat_completions, messages, responses, responses_compact."},
				{Name: "keys", Type: pluginapi.ConfigFieldTypeArray, Description: "Optional static key rules. Prefer key_hash over plaintext key."},
			},
		},
		Capabilities: runtimeCapabilities,
	}
}

func (l *limiter) trafficEnabledLocked() bool {
	caps := l.runtimeCapabilitiesLocked()
	return caps.FrontendAuthProvider || caps.RequestInterceptor || caps.ResponseInterceptor || caps.UsagePlugin
}

func (l *limiter) runtimeCapabilitiesLocked() capabilities {
	if !l.cfg.TrafficEnabled {
		return capabilities{ManagementAPI: true}
	}
	hasAuthKeys := len(l.configuredKeys) > 0 || len(l.state.Keys) > 0
	hasRequestPolicies := len(l.cfg.Policies) > 0 || len(l.cfg.EndpointOverrides) > 0 || anyKeyRequestPolicyLocked(l.configuredKeys) || anyKeyRequestPolicyLocked(l.state.Keys)
	hasResponsePolicies := len(l.cfg.Policies) > 0 || l.cfg.ExposeLimitHeaders || anyKeyResponsePolicyLocked(l.configuredKeys) || anyKeyResponsePolicyLocked(l.state.Keys)
	hasUsage := hasAuthKeys || len(l.cfg.Policies) > 0 || len(l.cfg.Pricing) > 0
	return capabilities{
		FrontendAuthProvider:          hasAuthKeys,
		FrontendAuthProviderExclusive: hasAuthKeys && l.cfg.Exclusive,
		RequestInterceptor:            hasRequestPolicies,
		ResponseInterceptor:           hasResponsePolicies,
		UsagePlugin:                   hasUsage,
		ManagementAPI:                 true,
	}
}

func anyKeyRequestPolicyLocked(keys map[string]keyRule) bool {
	for _, rule := range keys {
		if len(rule.EndpointOverrides) > 0 || requestPolicyConfigured(rule.Request) {
			return true
		}
	}
	return false
}

func anyKeyResponsePolicyLocked(keys map[string]keyRule) bool {
	for _, rule := range keys {
		if responsePolicyConfigured(rule.Response) || errorResponseConfigured(rule.ErrorResponse) {
			return true
		}
	}
	return false
}

func (l *limiter) trafficConfigEnabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cfg.TrafficEnabled
}

func authenticate(raw []byte) ([]byte, error) {
	if !currentLimiter.trafficConfigEnabled() {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	var req pluginapi.FrontendAuthRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	credential, source := extractCredential(req.Headers, req.Query)
	if credential == "" {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	model := requestedModel(req.Body)
	provider := providerFromRequest(req)
	now := time.Now().UTC()
	currentLimiter.mu.Lock()
	rule, ok := currentLimiter.findKeyByCredentialLocked(credential)
	if !ok || !rule.usable(now) || !keyPolicyAllowed(rule, model, provider, now) {
		currentLimiter.mu.Unlock()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	usage := currentLimiter.ensureUsageLocked(rule.ID)
	if !withinQuota(rule, usage, now) || !currentLimiter.allowRequestLocked(rule, usage, now) {
		_ = currentLimiter.saveStateLocked()
		currentLimiter.mu.Unlock()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	ctx := endpointOverrideContext{KeyID: rule.ID, Provider: provider, Model: model, RequestedModel: model, RequestPath: normalizeEndpointPath(req.Path)}
	denied, deniedPolicy, deniedMessage, dryRun := currentLimiter.authDenyDecisionLocked(ctx)
	if denied && !dryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: deniedPolicy, Action: "deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, Message: deniedMessage})
		_ = currentLimiter.saveStateLocked()
		currentLimiter.mu.Unlock()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	if denied && dryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: deniedPolicy, Action: "would_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, DryRun: true, Message: deniedMessage})
	}
	quotaDenied, quotaPolicy, quotaMessage, quotaDryRun := currentLimiter.policyQuotaDecisionLocked(ctx, rule, now)
	if quotaDenied && !quotaDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: quotaPolicy, Action: "quota_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, Message: quotaMessage})
		_ = currentLimiter.saveStateLocked()
		currentLimiter.mu.Unlock()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	if quotaDenied && quotaDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: quotaPolicy, Action: "would_quota_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, DryRun: true, Message: quotaMessage})
	}
	concurrencyDenied, concurrencyPolicy, concurrencyMessage, concurrencyDryRun := currentLimiter.policyConcurrencyDecisionLocked(ctx, rule)
	if concurrencyDenied && !concurrencyDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: concurrencyPolicy, Action: "concurrency_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, Message: concurrencyMessage})
		_ = currentLimiter.saveStateLocked()
		currentLimiter.mu.Unlock()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	if concurrencyDenied && concurrencyDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: concurrencyPolicy, Action: "would_concurrency_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, DryRun: true, Message: concurrencyMessage})
	}
	errSave := currentLimiter.saveStateLocked()
	currentLimiter.mu.Unlock()
	if errSave != nil && currentLimiter.cfg.FailClosed {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	metadata := map[string]string{
		"provider":        pluginID,
		"legacy_provider": legacyPluginID,
		"source":          source,
		"key_id":          rule.ID,
	}
	for key, value := range rule.Metadata {
		if reservedAuthMetadataKey(key) {
			continue
		}
		metadata[key] = value
	}
	if rule.Tenant != "" {
		metadata["tenant"] = rule.Tenant
	}
	if rule.Plan != "" {
		metadata["plan"] = rule.Plan
	}
	return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: true, Principal: rule.ID, Metadata: metadata})
}

func reservedAuthMetadataKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "provider", "legacy_provider", "source", "key_id", "tenant", "plan":
		return true
	default:
		return false
	}
}

func interceptRequest(raw []byte) ([]byte, error) {
	if !currentLimiter.trafficConfigEnabled() {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	var req pluginapi.RequestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	headers := http.Header{}
	headers.Set("X-CLIProxy-Policy-Hub", pluginID)
	clearHeaders := []string{}
	body := append([]byte(nil), req.Body...)
	dryRun := currentLimiter.dryRun()
	ctx := requestPolicyContext(req)
	if rule, ok := currentLimiter.keyRuleByID(ctx.KeyID); ok {
		changed, errApply := applyRequestPolicy(rule.Request, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && rule.ID != "" && !dryRun {
			headers.Add("X-CLIProxy-Policy-Hub-Match", "key:"+rule.ID)
		}
	}
	for _, policy := range currentLimiter.matchingPolicies(ctx) {
		if policy.Deny {
			currentLimiter.recordPolicyEvent(policyEvent{At: time.Now().UTC(), Policy: policy.Name, Action: dryRunAction("would_deny", "deny", dryRun), KeyID: ctx.KeyID, Provider: ctx.Provider, Model: ctx.Model, RequestPath: ctx.RequestPath, DryRun: dryRun, Message: policy.denyMessage()})
		}
		changed, errApply := applyRequestPolicy(policy.Request, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && policy.Name != "" {
			currentLimiter.recordPolicyEvent(policyEvent{At: time.Now().UTC(), Policy: policy.Name, Action: dryRunAction("would_mutate_request", "mutate_request", dryRun), KeyID: ctx.KeyID, Provider: ctx.Provider, Model: ctx.Model, RequestPath: ctx.RequestPath, DryRun: dryRun})
			if !dryRun {
				headers.Add("X-CLIProxy-Policy-Hub-Match", policy.Name)
			}
		}
	}
	if dryRun {
		body = append([]byte(nil), req.Body...)
		clearHeaders = nil
		headers = http.Header{}
		headers.Set("X-CLIProxy-Policy-Hub-Dry-Run", "true")
	}
	if !dryRun && req.ToFormat != "" {
		if target, matched := currentLimiter.endpointOverride(req); matched != "" {
			if target != "" {
				headers.Set(interfaceOverrideHeader, target)
				headers.Set(interfaceOverrideMatchHeader, matched)
			}
		}
	}
	response := pluginapi.RequestInterceptResponse{Headers: headers, ClearHeaders: clearHeaders}
	if !bytes.Equal(body, req.Body) {
		response.Body = body
	}
	return okEnvelope(response)
}

func (l *limiter) keyRuleByID(keyID string) (keyRule, bool) {
	if l == nil || strings.TrimSpace(keyID) == "" {
		return keyRule{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyRuleByIDLocked(keyID)
}

func interceptResponse(raw []byte) ([]byte, error) {
	if !currentLimiter.trafficConfigEnabled() {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	var req pluginapi.ResponseInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	headers := http.Header{}
	clearHeaders := []string{}
	body := append([]byte(nil), req.Body...)
	dryRun := currentLimiter.dryRun()
	ctx := responsePolicyContext(req)
	if rule, ok := currentLimiter.keyRuleByID(ctx.KeyID); ok {
		if applyCustomErrorResponse(rule.ErrorResponse, &headers, &clearHeaders, &body) && rule.ID != "" && !dryRun {
			headers.Add("X-CLIProxy-Policy-Hub-Match", "key-error:"+rule.ID)
		}
		changed, errApply := applyResponsePolicy(rule.Response, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && rule.ID != "" && !dryRun {
			headers.Add("X-CLIProxy-Policy-Hub-Match", "key:"+rule.ID)
		}
	}
	for _, policy := range currentLimiter.matchingPolicies(ctx) {
		changed, errApply := applyResponsePolicy(policy.Response, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && policy.Name != "" {
			currentLimiter.recordPolicyEvent(policyEvent{At: time.Now().UTC(), Policy: policy.Name, Action: dryRunAction("would_mutate_response", "mutate_response", dryRun), KeyID: ctx.KeyID, Provider: ctx.Provider, Model: ctx.Model, RequestPath: ctx.RequestPath, DryRun: dryRun})
			if !dryRun {
				headers.Add("X-CLIProxy-Policy-Hub-Match", policy.Name)
			}
		}
	}
	if dryRun {
		body = append([]byte(nil), req.Body...)
		clearHeaders = nil
		headers = http.Header{}
		headers.Set("X-CLIProxy-Policy-Hub-Dry-Run", "true")
	}
	currentLimiter.mu.Lock()
	expose := currentLimiter.cfg.ExposeLimitHeaders
	currentLimiter.mu.Unlock()
	if expose {
		headers.Set("X-CLIProxy-Policy-Hub", pluginID)
	}
	response := pluginapi.ResponseInterceptResponse{Headers: headers, ClearHeaders: clearHeaders}
	if !bytes.Equal(body, req.Body) {
		response.Body = body
	}
	return okEnvelope(response)
}

func handleUsage(raw []byte) ([]byte, error) {
	if !currentLimiter.trafficConfigEnabled() {
		return okEnvelope(struct{}{})
	}
	var record pluginapi.UsageRecord
	if errUnmarshal := json.Unmarshal(raw, &record); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	keyID := strings.TrimSpace(record.APIKey)
	if keyID == "" {
		return okEnvelope(struct{}{})
	}
	now := time.Now().UTC()
	if !record.RequestedAt.IsZero() {
		now = record.RequestedAt.UTC()
	}
	currentLimiter.mu.Lock()
	if resolved, ok := currentLimiter.resolveKeyIDLocked(keyID); ok {
		keyID = resolved
	}
	usage := currentLimiter.ensureUsageLocked(keyID)
	tokens := record.Detail.TotalTokens
	if tokens == 0 {
		tokens = record.Detail.InputTokens + record.Detail.OutputTokens + record.Detail.ReasoningTokens
	}
	usage.TotalTokens += tokens
	usage.InputTokens += record.Detail.InputTokens
	usage.OutputTokens += record.Detail.OutputTokens
	usage.ReasoningTokens += record.Detail.ReasoningTokens
	usage.CachedTokens += record.Detail.CachedTokens
	usage.Requests++
	if record.Failed {
		usage.FailedRequests++
	}
	if usage.DailyTokens == nil {
		usage.DailyTokens = map[string]int64{}
	}
	if usage.MonthlyTokens == nil {
		usage.MonthlyTokens = map[string]int64{}
	}
	if usage.Models == nil {
		usage.Models = map[string]int64{}
	}
	if usage.DailyCost == nil {
		usage.DailyCost = map[string]float64{}
	}
	if usage.MonthlyCost == nil {
		usage.MonthlyCost = map[string]float64{}
	}
	usage.DailyTokens[dayKey(now)] += tokens
	usage.MonthlyTokens[monthKey(now)] += tokens
	usage.HourlyTokens[hourKey(now)] += tokens
	if record.Model != "" {
		usage.Models[record.Model] += tokens
	}
	cost := currentLimiter.usageCost(record)
	if cost > 0 {
		usage.TotalCost += cost
		usage.DailyCost[dayKey(now)] += cost
		usage.MonthlyCost[monthKey(now)] += cost
	}
	usage.LastUsedAt = time.Now().UTC()
	currentLimiter.releasePolicyConcurrencyLocked(record, keyID)
	currentLimiter.updatePolicyTokenUsageLocked(record, keyID, tokens, cost, now)
	currentLimiter.appendEventLocked(usageEvent{
		At:           time.Now().UTC(),
		KeyID:        keyID,
		Provider:     record.Provider,
		Model:        record.Model,
		TotalTokens:  tokens,
		InputTokens:  record.Detail.InputTokens,
		OutputTokens: record.Detail.OutputTokens,
		Failed:       record.Failed,
	})
	errSave := currentLimiter.saveStateLocked()
	currentLimiter.mu.Unlock()
	if errSave != nil {
		return nil, errSave
	}
	return okEnvelope(struct{}{})
}

func registerManagement() ([]byte, error) {
	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: "/plugins/cpa-policy-hub/status"},
			{Method: http.MethodGet, Path: "/plugins/cpa-policy-hub/keys"},
			{Method: http.MethodPost, Path: "/plugins/cpa-policy-hub/keys"},
			{Method: http.MethodPatch, Path: "/plugins/cpa-policy-hub/keys"},
			{Method: http.MethodDelete, Path: "/plugins/cpa-policy-hub/keys"},
			{Method: http.MethodGet, Path: "/plugins/cpa-policy-hub/usage"},
			{Method: http.MethodGet, Path: "/plugins/cpa-policy-hub/events"},
			{Method: http.MethodGet, Path: "/plugins/cpa-policy-hub/policy-log"},
			{Method: http.MethodPost, Path: "/plugins/cpa-policy-hub/reset"},
			{Method: http.MethodGet, Path: "/plugins/cpa-policy-hub/export"},
			{Method: http.MethodPost, Path: "/plugins/cpa-policy-hub/import"},
			{Method: http.MethodGet, Path: "/plugins/api-key-token-limiter/status"},
			{Method: http.MethodGet, Path: "/plugins/api-key-token-limiter/keys"},
			{Method: http.MethodPost, Path: "/plugins/api-key-token-limiter/keys"},
			{Method: http.MethodPatch, Path: "/plugins/api-key-token-limiter/keys"},
			{Method: http.MethodDelete, Path: "/plugins/api-key-token-limiter/keys"},
			{Method: http.MethodGet, Path: "/plugins/api-key-token-limiter/usage"},
			{Method: http.MethodGet, Path: "/plugins/api-key-token-limiter/events"},
			{Method: http.MethodGet, Path: "/plugins/api-key-token-limiter/policy-log"},
			{Method: http.MethodPost, Path: "/plugins/api-key-token-limiter/reset"},
			{Method: http.MethodGet, Path: "/plugins/api-key-token-limiter/export"},
			{Method: http.MethodPost, Path: "/plugins/api-key-token-limiter/import"},
		},
		Resources: []pluginapi.ResourceRoute{
			{Path: "/index.html", Menu: pluginDisplayName, Description: "Manage and inspect CPA gateway policy state."},
		},
	})
}

func handleManagement(raw []byte) ([]byte, error) {
	if len(raw) > maxManagementBodyBytes {
		return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusRequestEntityTooLarge, Body: []byte(`{"error":"management request too large"}`), Headers: jsonHeaders()})
	}
	var req managementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	path := strings.TrimSuffix(req.Path, "/")
	resourcePrefix := "/v0/resource/plugins/" + pluginID
	if req.Method == http.MethodGet && (path == resourcePrefix || path == resourcePrefix+"/index.html" || strings.HasPrefix(path, resourcePrefix+"/status")) {
		return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: htmlHeaders(), Body: []byte(finalStatusHTML())})
	}
	if strings.HasSuffix(path, "/status") && req.Method == http.MethodGet {
		return managementStatus(req)
	}
	if strings.HasSuffix(path, "/keys") {
		switch req.Method {
		case http.MethodGet:
			return managementListKeys()
		case http.MethodPost:
			return managementCreateKey(req.Body)
		case http.MethodPatch:
			return managementPatchKey(req.Body)
		case http.MethodDelete:
			return managementDeleteKey(req)
		}
	}
	if strings.HasSuffix(path, "/usage") && req.Method == http.MethodGet {
		return managementUsage(req)
	}
	if strings.HasSuffix(path, "/events") && req.Method == http.MethodGet {
		return managementEvents(req)
	}
	if strings.HasSuffix(path, "/policy-log") && req.Method == http.MethodGet {
		return managementPolicyLog(req)
	}
	if strings.HasSuffix(path, "/reset") && req.Method == http.MethodPost {
		return managementReset(req)
	}
	if strings.HasSuffix(path, "/export") && req.Method == http.MethodGet {
		return managementExport()
	}
	if strings.HasSuffix(path, "/import") && req.Method == http.MethodPost {
		return managementImport(req.Body)
	}
	return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusNotFound, Body: []byte(`{"error":"not found"}`), Headers: jsonHeaders()})
}

func managementStatus(req managementRequest) ([]byte, error) {
	if strings.Contains(req.Path, "/v0/resource/plugins/") {
		return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: htmlHeaders(), Body: []byte(finalStatusHTML())})
	}
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	trafficEnabled := currentLimiter.trafficEnabledLocked()
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{
		"plugin":                 pluginID,
		"name":                   pluginDisplayName,
		"legacy_plugin":          legacyPluginID,
		"version":                pluginVersion,
		"capabilities":           currentLimiter.runtimeCapabilitiesLocked(),
		"traffic_enabled":        trafficEnabled,
		"traffic_config_enabled": currentLimiter.cfg.TrafficEnabled,
		"exclusive":              currentLimiter.cfg.Exclusive,
		"storage_path":           currentLimiter.cfg.StoragePath,
		"config_path":            currentLimiter.cfg.ConfigPath,
		"manage_config_api_keys": currentLimiter.cfg.ManageConfigAPIKeys,
		"config_load_error":      currentLimiter.configLoadError,
		"policies":               len(currentLimiter.cfg.Policies),
		"endpoint_rules":         len(currentLimiter.cfg.EndpointOverrides),
		"configured_keys":        len(currentLimiter.configuredKeys),
		"managed_keys":           len(currentLimiter.state.Keys),
		"tracked_keys":           len(currentLimiter.state.Usage),
		"policy_events":          len(currentLimiter.state.PolicyLog),
		"policy_counters":        len(currentLimiter.state.Policies),
		"active_counters":        len(currentLimiter.state.Active),
		"updated_at":             currentLimiter.state.UpdatedAt,
	}))
}

func managementListKeys() ([]byte, error) {
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	keys := currentLimiter.listKeysLocked()
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"keys": keys}))
}

func managementCreateKey(raw []byte) ([]byte, error) {
	var rule keyRule
	if len(bytes.TrimSpace(raw)) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &rule); errUnmarshal != nil {
			return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": errUnmarshal.Error()}))
		}
	}
	apiKey := strings.TrimSpace(rule.Key)
	if apiKey == "" && strings.TrimSpace(rule.KeyHash) == "" {
		generated, errGenerate := randomHex(24)
		if errGenerate != nil {
			return nil, errGenerate
		}
		apiKey = "cpa_" + generated
		rule.Key = apiKey
	}
	currentLimiter.mu.Lock()
	normalized, ok := normalizeKeyRule(rule, currentLimiter.cfg, "managed")
	if !ok {
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "key, key_hash, or generated key is required"}))
	}
	if _, exists := currentLimiter.configuredKeys[normalized.ID]; exists {
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusConflict, map[string]any{"error": "a configured key with this id already exists"}))
	}
	if currentLimiter.state.Keys == nil {
		currentLimiter.state.Keys = map[string]keyRule{}
	}
	normalized.Key = ""
	currentLimiter.state.Keys[normalized.ID] = normalized
	errSave := currentLimiter.saveStateLocked()
	currentLimiter.mu.Unlock()
	if errSave != nil {
		return nil, errSave
	}
	normalized.KeyHash = maskHash(normalized.KeyHash)
	return okEnvelope(jsonResponse(http.StatusCreated, createKeyResponse{Key: normalized, APIKey: apiKey}))
}

func managementPatchKey(raw []byte) ([]byte, error) {
	var rule keyRule
	if errUnmarshal := json.Unmarshal(raw, &rule); errUnmarshal != nil {
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": errUnmarshal.Error()}))
	}
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "id is required"}))
	}
	currentLimiter.mu.Lock()
	existing, ok := currentLimiter.state.Keys[rule.ID]
	if !ok {
		existing, ok = currentLimiter.configuredKeys[rule.ID]
	}
	if !ok {
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusNotFound, map[string]any{"error": "key not found"}))
	}
	rule.Source = "managed"
	if strings.TrimSpace(rule.Key) == "" && strings.TrimSpace(rule.KeyHash) == "" {
		rule.KeyHash = existing.KeyHash
	}
	rule = mergeKeyRulePatch(existing, rule)
	normalized, okNormalize := normalizeKeyRule(rule, currentLimiter.cfg, "managed")
	if !okNormalize {
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "key_hash is required"}))
	}
	if normalized.ID != rule.ID {
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "id cannot be changed by patch"}))
	}
	currentLimiter.state.Keys[normalized.ID] = normalized
	errSave := currentLimiter.saveStateLocked()
	currentLimiter.mu.Unlock()
	if errSave != nil {
		return nil, errSave
	}
	normalized.KeyHash = maskHash(normalized.KeyHash)
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"key": normalized}))
}

func mergeKeyRulePatch(existing keyRule, patch keyRule) keyRule {
	if patch.Name == "" {
		patch.Name = existing.Name
	}
	if patch.Tenant == "" {
		patch.Tenant = existing.Tenant
	}
	if patch.Plan == "" {
		patch.Plan = existing.Plan
	}
	if patch.ExpiresAt == "" {
		patch.ExpiresAt = existing.ExpiresAt
	}
	if len(patch.AllowedModels) == 0 {
		patch.AllowedModels = existing.AllowedModels
	}
	if len(patch.DeniedModels) == 0 {
		patch.DeniedModels = existing.DeniedModels
	}
	if len(patch.AllowedProviders) == 0 {
		patch.AllowedProviders = existing.AllowedProviders
	}
	if len(patch.DeniedProviders) == 0 {
		patch.DeniedProviders = existing.DeniedProviders
	}
	if len(patch.TimeWindows) == 0 {
		patch.TimeWindows = existing.TimeWindows
	}
	if len(patch.EndpointOverrides) == 0 {
		patch.EndpointOverrides = existing.EndpointOverrides
	}
	if !requestPolicyConfigured(patch.Request) {
		patch.Request = existing.Request
	}
	if !responsePolicyConfigured(patch.Response) {
		patch.Response = existing.Response
	}
	if !errorResponseConfigured(patch.ErrorResponse) {
		patch.ErrorResponse = existing.ErrorResponse
	}
	if len(patch.Metadata) == 0 {
		patch.Metadata = existing.Metadata
	}
	return patch
}

func managementDeleteKey(req managementRequest) ([]byte, error) {
	id := strings.TrimSpace(req.Query.Get("id"))
	if id == "" && len(bytes.TrimSpace(req.Body)) > 0 {
		var body struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(req.Body, &body)
		id = strings.TrimSpace(body.ID)
	}
	if id == "" {
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "id is required"}))
	}
	currentLimiter.mu.Lock()
	if _, ok := currentLimiter.state.Keys[id]; !ok {
		currentLimiter.mu.Unlock()
		if _, configured := currentLimiter.configuredKeys[id]; configured {
			return okEnvelope(jsonResponse(http.StatusConflict, map[string]any{"error": "configured key has no runtime override to delete"}))
		}
		return okEnvelope(jsonResponse(http.StatusNotFound, map[string]any{"error": "key not found"}))
	}
	delete(currentLimiter.state.Keys, id)
	errSave := currentLimiter.saveStateLocked()
	currentLimiter.mu.Unlock()
	if errSave != nil {
		return nil, errSave
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"deleted": id}))
}

func managementUsage(req managementRequest) ([]byte, error) {
	id := strings.TrimSpace(req.Query.Get("id"))
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	if id != "" {
		return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"id": id, "usage": currentLimiter.state.Usage[id].clone()}))
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"usage": cloneUsageMap(currentLimiter.state.Usage), "policy_usage": cloneUsageMap(currentLimiter.state.Policies), "active": cloneIntMap(currentLimiter.state.Active)}))
}

func managementEvents(req managementRequest) ([]byte, error) {
	limit := 100
	if rawLimit := strings.TrimSpace(req.Query.Get("limit")); rawLimit != "" {
		if parsed, errParse := strconv.Atoi(rawLimit); errParse == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	events := currentLimiter.state.Events
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"events": events}))
}

func managementPolicyLog(req managementRequest) ([]byte, error) {
	limit := 100
	if rawLimit := strings.TrimSpace(req.Query.Get("limit")); rawLimit != "" {
		if parsed, errParse := strconv.Atoi(rawLimit); errParse == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	events := currentLimiter.state.PolicyLog
	if len(events) > limit {
		events = events[len(events)-limit:]
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"policy_log": events}))
}

func managementReset(req managementRequest) ([]byte, error) {
	reset := resetRequest{Target: strings.TrimSpace(req.Query.Get("target")), ID: strings.TrimSpace(req.Query.Get("id"))}
	if len(bytes.TrimSpace(req.Body)) > 0 {
		_ = json.Unmarshal(req.Body, &reset)
		reset.Target = strings.TrimSpace(reset.Target)
		reset.ID = strings.TrimSpace(reset.ID)
	}
	if reset.Target == "" {
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "target is required"}))
	}
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	switch strings.ToLower(reset.Target) {
	case "active":
		if reset.ID != "" {
			delete(currentLimiter.state.Active, reset.ID)
		} else {
			currentLimiter.state.Active = map[string]int{}
		}
	case "usage", "key_usage":
		if reset.ID != "" {
			delete(currentLimiter.state.Usage, reset.ID)
		} else {
			currentLimiter.state.Usage = map[string]*usageCounter{}
		}
	case "policy", "policy_usage", "policy_quota":
		if reset.ID != "" {
			delete(currentLimiter.state.Policies, reset.ID)
		} else {
			currentLimiter.state.Policies = map[string]*usageCounter{}
		}
	case "events":
		currentLimiter.state.Events = nil
	case "policy_log":
		currentLimiter.state.PolicyLog = nil
	case "all_counters":
		currentLimiter.state.Usage = map[string]*usageCounter{}
		currentLimiter.state.Policies = map[string]*usageCounter{}
		currentLimiter.state.Active = map[string]int{}
		currentLimiter.state.Events = nil
		currentLimiter.state.PolicyLog = nil
	case "keys", "managed_keys":
		if reset.ID != "" {
			delete(currentLimiter.state.Keys, reset.ID)
		} else {
			return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "resetting all managed keys requires target managed_keys_all"}))
		}
	case "managed_keys_all":
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "bulk managed key deletion is not supported by reset; delete keys individually"}))
	default:
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "unsupported target"}))
	}
	if errSave := currentLimiter.saveStateLocked(); errSave != nil {
		return nil, errSave
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"reset": reset.Target, "id": reset.ID}))
}

func managementExport() ([]byte, error) {
	currentLimiter.mu.Lock()
	defer currentLimiter.mu.Unlock()
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{
		"plugin":  pluginID,
		"version": pluginVersion,
		"state":   currentLimiter.state,
	}))
}

func managementImport(raw []byte) ([]byte, error) {
	var request importStateRequest
	if errUnmarshal := json.Unmarshal(raw, &request); errUnmarshal != nil {
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": errUnmarshal.Error()}))
	}
	normalizeImportedState(&request.State)
	currentLimiter.mu.Lock()
	if request.Replace {
		for id, key := range request.State.Keys {
			key.Key = ""
			key.KeyHash = normalizeHash(key.KeyHash)
			if !validSHA256Hash(key.KeyHash) {
				delete(request.State.Keys, id)
				continue
			}
			request.State.Keys[id] = key
		}
		currentLimiter.state = request.State
	} else {
		mergeState(&currentLimiter.state, request.State)
	}
	if errSave := currentLimiter.saveStateLocked(); errSave != nil {
		currentLimiter.mu.Unlock()
		return nil, errSave
	}
	currentLimiter.mu.Unlock()
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"imported": true, "replace": request.Replace}))
}

func normalizeImportedState(state *persistedState) {
	if state.Keys == nil {
		state.Keys = map[string]keyRule{}
	}
	if state.Usage == nil {
		state.Usage = map[string]*usageCounter{}
	}
	if state.Policies == nil {
		state.Policies = map[string]*usageCounter{}
	}
	if state.Active == nil {
		state.Active = map[string]int{}
	}
	if state.Events == nil {
		state.Events = []usageEvent{}
	}
	if state.PolicyLog == nil {
		state.PolicyLog = []policyEvent{}
	}
	for _, usage := range state.Usage {
		ensureUsageMaps(usage)
	}
	for _, usage := range state.Policies {
		ensureUsageMaps(usage)
	}
}

func mergeState(dst *persistedState, src persistedState) {
	normalizeImportedState(dst)
	normalizeImportedState(&src)
	for id, key := range src.Keys {
		key.Key = ""
		key.KeyHash = normalizeHash(key.KeyHash)
		if !validSHA256Hash(key.KeyHash) {
			continue
		}
		dst.Keys[id] = key
	}
	for id, usage := range src.Usage {
		dst.Usage[id] = usage
	}
	for id, usage := range src.Policies {
		dst.Policies[id] = usage
	}
	for id, active := range src.Active {
		dst.Active[id] = active
	}
	dst.Events = append(dst.Events, src.Events...)
	if len(dst.Events) > 1000 {
		dst.Events = append([]usageEvent(nil), dst.Events[len(dst.Events)-1000:]...)
	}
	dst.PolicyLog = append(dst.PolicyLog, src.PolicyLog...)
	if len(dst.PolicyLog) > 1000 {
		dst.PolicyLog = append([]policyEvent(nil), dst.PolicyLog[len(dst.PolicyLog)-1000:]...)
	}
}

func cloneUsageMap(values map[string]*usageCounter) map[string]*usageCounter {
	if values == nil {
		return map[string]*usageCounter{}
	}
	out := make(map[string]*usageCounter, len(values))
	for key, value := range values {
		out[key] = value.clone()
	}
	return out
}

func cloneInt64Map(values map[string]int64) map[string]int64 {
	if values == nil {
		return nil
	}
	out := make(map[string]int64, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneIntMap(values map[string]int) map[string]int {
	if values == nil {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneFloatMap(values map[string]float64) map[string]float64 {
	if values == nil {
		return nil
	}
	out := make(map[string]float64, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func (l *limiter) findKeyByCredentialLocked(credential string) (keyRule, bool) {
	hash := hashAPIKey(credential)
	for _, rule := range l.state.Keys {
		if hashMatches(rule.KeyHash, hash) {
			return rule, true
		}
	}
	for _, rule := range l.configuredKeys {
		if hashMatches(rule.KeyHash, hash) {
			return rule, true
		}
	}
	return keyRule{}, false
}

func (l *limiter) resolveKeyIDLocked(value string) (string, bool) {
	if _, ok := l.state.Keys[value]; ok {
		return value, true
	}
	if _, ok := l.configuredKeys[value]; ok {
		return value, true
	}
	hash := hashAPIKey(value)
	for _, rule := range l.state.Keys {
		if hashMatches(rule.KeyHash, hash) {
			return rule.ID, true
		}
	}
	for _, rule := range l.configuredKeys {
		if hashMatches(rule.KeyHash, hash) {
			return rule.ID, true
		}
	}
	return "", false
}

func (l *limiter) keyRuleByIDLocked(keyID string) (keyRule, bool) {
	if rule, ok := l.state.Keys[keyID]; ok {
		return rule, true
	}
	if rule, ok := l.configuredKeys[keyID]; ok {
		return rule, true
	}
	return keyRule{}, false
}

func (l *limiter) ensureUsageLocked(keyID string) *usageCounter {
	if l.state.Usage == nil {
		l.state.Usage = map[string]*usageCounter{}
	}
	usage := l.state.Usage[keyID]
	if usage == nil {
		usage = &usageCounter{}
		l.state.Usage[keyID] = usage
	}
	if usage.DailyTokens == nil {
		usage.DailyTokens = map[string]int64{}
	}
	if usage.MonthlyTokens == nil {
		usage.MonthlyTokens = map[string]int64{}
	}
	if usage.RequestsByMinute == nil {
		usage.RequestsByMinute = map[string]int{}
	}
	if usage.Models == nil {
		usage.Models = map[string]int64{}
	}
	if usage.HourlyTokens == nil {
		usage.HourlyTokens = map[string]int64{}
	}
	if usage.HourlyRequests == nil {
		usage.HourlyRequests = map[string]int64{}
	}
	return usage
}

func (l *limiter) ensurePolicyUsageLocked(policyKey string) *usageCounter {
	if l.state.Policies == nil {
		l.state.Policies = map[string]*usageCounter{}
	}
	usage := l.state.Policies[policyKey]
	if usage == nil {
		usage = &usageCounter{}
		l.state.Policies[policyKey] = usage
	}
	ensureUsageMaps(usage)
	return usage
}

func ensureUsageMaps(usage *usageCounter) {
	if usage == nil {
		return
	}
	if usage.DailyTokens == nil {
		usage.DailyTokens = map[string]int64{}
	}
	if usage.MonthlyTokens == nil {
		usage.MonthlyTokens = map[string]int64{}
	}
	if usage.RequestsByMinute == nil {
		usage.RequestsByMinute = map[string]int{}
	}
	if usage.Models == nil {
		usage.Models = map[string]int64{}
	}
	if usage.DailyCost == nil {
		usage.DailyCost = map[string]float64{}
	}
	if usage.MonthlyCost == nil {
		usage.MonthlyCost = map[string]float64{}
	}
	if usage.HourlyTokens == nil {
		usage.HourlyTokens = map[string]int64{}
	}
	if usage.HourlyRequests == nil {
		usage.HourlyRequests = map[string]int64{}
	}
}

func (l *limiter) allowRequestLocked(rule keyRule, usage *usageCounter, now time.Time) bool {
	ensureUsageMaps(usage)
	if rule.HourlyRequestLimit > 0 && usage.HourlyRequests[hourKey(now)] >= rule.HourlyRequestLimit {
		return false
	}
	limit := rule.RequestLimitPerMinute
	if limit <= 0 {
		if rule.HourlyRequestLimit > 0 {
			usage.HourlyRequests[hourKey(now)]++
		}
		return true
	}
	minute := minuteKey(now)
	pruneRequestMinutes(usage, now.Add(-10*time.Minute))
	if usage.RequestsByMinute[minute] >= limit {
		return false
	}
	usage.RequestsByMinute[minute]++
	if rule.HourlyRequestLimit > 0 {
		usage.HourlyRequests[hourKey(now)]++
	}
	return true
}

func (l *limiter) policyQuotaDecisionLocked(ctx endpointOverrideContext, rule keyRule, now time.Time) (bool, string, string, bool) {
	for _, policy := range l.cfg.Policies {
		if !policy.matches(ctx) || !policy.Quota.enabled() {
			continue
		}
		key := policyQuotaKey(policy, rule)
		usage := l.ensurePolicyUsageLocked(key)
		estimatedTokens := policy.Quota.EstimatedTokensPerCall
		estimatedCost := l.estimatedCostForModel(firstNonEmpty(ctx.Model, ctx.RequestedModel))
		if !policyQuotaWithin(policy.Quota, usage, now, estimatedTokens, estimatedCost) {
			return true, policy.Name, "policy quota exceeded", l.cfg.DryRun
		}
		if !l.cfg.DryRun && !policyQuotaAllowRequest(policy.Quota, usage, now) {
			return true, policy.Name, "policy request rate limit exceeded", false
		}
		if l.cfg.DryRun && !policyQuotaWouldAllowRequest(policy.Quota, usage, now) {
			return true, policy.Name, "policy request rate limit would be exceeded", true
		}
	}
	return false, "", "", l.cfg.DryRun
}

func policyQuotaKey(policy policyRule, rule keyRule) string {
	name := strings.TrimSpace(policy.Name)
	if name == "" {
		name = "unnamed"
	}
	scope := strings.ToLower(strings.TrimSpace(policy.Quota.Scope))
	switch scope {
	case "tenant":
		return "tenant:" + firstNonEmpty(rule.Tenant, "default") + ":" + name
	case "plan":
		return "plan:" + firstNonEmpty(rule.Plan, "default") + ":" + name
	case "key":
		return "key:" + firstNonEmpty(rule.ID, "unknown") + ":" + name
	case "global", "policy", "":
		return "policy:" + name
	default:
		return scope + ":" + name
	}
}

func (q policyQuota) enabled() bool {
	return q.DailyTokenLimit > 0 || q.MonthlyTokenLimit > 0 || q.TotalTokenLimit > 0 || q.RequestLimitPerMinute > 0 || q.DailyRequestLimit > 0 || q.MonthlyRequestLimit > 0 || q.TotalRequestLimit > 0 || q.DailyCostLimit > 0 || q.MonthlyCostLimit > 0 || q.TotalCostLimit > 0
}

func policyQuotaWithin(q policyQuota, usage *usageCounter, now time.Time, estimatedTokens int64, estimatedCost float64) bool {
	if usage == nil {
		return true
	}
	ensureUsageMaps(usage)
	if q.TotalTokenLimit > 0 && usage.TotalTokens+estimatedTokens >= q.TotalTokenLimit {
		return false
	}
	if q.DailyTokenLimit > 0 && usage.DailyTokens[dayKey(now)]+estimatedTokens > q.DailyTokenLimit {
		return false
	}
	if q.MonthlyTokenLimit > 0 && usage.MonthlyTokens[monthKey(now)]+estimatedTokens > q.MonthlyTokenLimit {
		return false
	}
	if q.TotalCostLimit > 0 && usage.TotalCost+estimatedCost > q.TotalCostLimit {
		return false
	}
	if q.DailyCostLimit > 0 && usage.DailyCost[dayKey(now)]+estimatedCost > q.DailyCostLimit {
		return false
	}
	if q.MonthlyCostLimit > 0 && usage.MonthlyCost[monthKey(now)]+estimatedCost > q.MonthlyCostLimit {
		return false
	}
	if q.TotalRequestLimit > 0 && usage.Requests >= q.TotalRequestLimit {
		return false
	}
	if q.DailyRequestLimit > 0 && usage.DailyTokens[policyRequestDayKey(now)] >= q.DailyRequestLimit {
		return false
	}
	if q.MonthlyRequestLimit > 0 && usage.MonthlyTokens[policyRequestMonthKey(now)] >= q.MonthlyRequestLimit {
		return false
	}
	return true
}

func policyQuotaAllowRequest(q policyQuota, usage *usageCounter, now time.Time) bool {
	ensureUsageMaps(usage)
	if q.RequestLimitPerMinute <= 0 {
		usage.Requests++
		usage.DailyTokens[policyRequestDayKey(now)]++
		usage.MonthlyTokens[policyRequestMonthKey(now)]++
		return true
	}
	minute := minuteKey(now)
	pruneRequestMinutes(usage, now.Add(-10*time.Minute))
	if usage.RequestsByMinute[minute] >= q.RequestLimitPerMinute {
		return false
	}
	usage.RequestsByMinute[minute]++
	usage.Requests++
	usage.DailyTokens[policyRequestDayKey(now)]++
	usage.MonthlyTokens[policyRequestMonthKey(now)]++
	return true
}

func policyQuotaWouldAllowRequest(q policyQuota, usage *usageCounter, now time.Time) bool {
	if q.RequestLimitPerMinute <= 0 {
		return true
	}
	ensureUsageMaps(usage)
	minute := minuteKey(now)
	pruneRequestMinutes(usage, now.Add(-10*time.Minute))
	return usage.RequestsByMinute[minute] < q.RequestLimitPerMinute
}

func (l *limiter) policyConcurrencyDecisionLocked(ctx endpointOverrideContext, rule keyRule) (bool, string, string, bool) {
	for _, policy := range l.cfg.Policies {
		if !policy.matches(ctx) || policy.Quota.ConcurrencyLimit <= 0 {
			continue
		}
		key := policyQuotaKey(policy, rule)
		active := l.state.Active[key]
		if active >= policy.Quota.ConcurrencyLimit {
			return true, policy.Name, "policy concurrency limit exceeded", l.cfg.DryRun
		}
		if !l.cfg.DryRun {
			l.state.Active[key] = active + 1
			usage := l.ensurePolicyUsageLocked(key)
			if l.state.Active[key] > usage.MaxActive {
				usage.MaxActive = l.state.Active[key]
			}
		}
	}
	return false, "", "", l.cfg.DryRun
}

func (l *limiter) releasePolicyConcurrencyLocked(record pluginapi.UsageRecord, keyID string) {
	if l.state.Active == nil {
		return
	}
	rule, _ := l.keyRuleByIDLocked(keyID)
	ctx := endpointOverrideContext{
		KeyID:          keyID,
		Provider:       record.Provider,
		Model:          record.Model,
		RequestedModel: firstNonEmpty(record.Alias, record.Model),
	}
	for _, policy := range l.cfg.Policies {
		if !policy.matches(ctx) || policy.Quota.ConcurrencyLimit <= 0 {
			continue
		}
		key := policyQuotaKey(policy, rule)
		if l.state.Active[key] <= 1 {
			delete(l.state.Active, key)
			continue
		}
		l.state.Active[key]--
	}
}

func (l *limiter) updatePolicyTokenUsageLocked(record pluginapi.UsageRecord, keyID string, tokens int64, cost float64, now time.Time) {
	if tokens <= 0 && cost <= 0 {
		return
	}
	rule, _ := l.keyRuleByIDLocked(keyID)
	ctx := endpointOverrideContext{
		KeyID:          keyID,
		Provider:       record.Provider,
		Model:          record.Model,
		RequestedModel: firstNonEmpty(record.Alias, record.Model),
	}
	for _, policy := range l.cfg.Policies {
		if !policy.matches(ctx) || !policy.Quota.enabled() {
			continue
		}
		usage := l.ensurePolicyUsageLocked(policyQuotaKey(policy, rule))
		usage.TotalTokens += tokens
		usage.InputTokens += record.Detail.InputTokens
		usage.OutputTokens += record.Detail.OutputTokens
		usage.ReasoningTokens += record.Detail.ReasoningTokens
		usage.CachedTokens += record.Detail.CachedTokens
		usage.DailyTokens[dayKey(now)] += tokens
		usage.MonthlyTokens[monthKey(now)] += tokens
		if cost > 0 {
			usage.TotalCost += cost
			usage.DailyCost[dayKey(now)] += cost
			usage.MonthlyCost[monthKey(now)] += cost
		}
		if record.Model != "" {
			usage.Models[record.Model] += tokens
		}
		if record.Failed {
			usage.FailedRequests++
		}
		usage.LastUsedAt = time.Now().UTC()
	}
}

func (l *limiter) usageCost(record pluginapi.UsageRecord) float64 {
	pricing, ok := l.pricingForModel(firstNonEmpty(record.Model, record.Alias))
	if !ok {
		return 0
	}
	return pricing.cost(record.Detail)
}

func (l *limiter) estimatedCostForModel(model string) float64 {
	pricing, ok := l.pricingForModel(model)
	if !ok {
		return 0
	}
	return pricing.cost(pluginapi.UsageDetail{
		InputTokens:     pricing.EstimatedInput,
		OutputTokens:    pricing.EstimatedOutput,
		ReasoningTokens: pricing.EstimatedReasoning,
	})
}

func (l *limiter) pricingForModel(model string) (pricingRule, bool) {
	model = strings.ToLower(strings.TrimSpace(model))
	for _, pricing := range l.cfg.Pricing {
		pattern := strings.ToLower(strings.TrimSpace(pricing.Model))
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == model || wildcardMatch(pattern, model) {
			return pricing, true
		}
	}
	return pricingRule{}, false
}

func (p pricingRule) cost(detail pluginapi.UsageDetail) float64 {
	input := float64(detail.InputTokens)
	output := float64(detail.OutputTokens)
	reasoning := float64(detail.ReasoningTokens)
	cached := float64(detail.CachedTokens)
	if cached == 0 {
		cached = float64(detail.CacheReadTokens + detail.CacheCreationTokens)
	}
	cost := p.FlatRequestCost
	cost += input * p.InputPer1M / 1_000_000
	cost += output * p.OutputPer1M / 1_000_000
	cost += reasoning * p.ReasoningPer1M / 1_000_000
	cost += cached * p.CachedInputPer1M / 1_000_000
	return cost
}

func (l *limiter) appendEventLocked(event usageEvent) {
	l.state.Events = append(l.state.Events, event)
	if len(l.state.Events) > 1000 {
		l.state.Events = append([]usageEvent(nil), l.state.Events[len(l.state.Events)-1000:]...)
	}
}

func (l *limiter) appendPolicyEventLocked(event policyEvent) {
	l.state.PolicyLog = append(l.state.PolicyLog, event)
	if len(l.state.PolicyLog) > 1000 {
		l.state.PolicyLog = append([]policyEvent(nil), l.state.PolicyLog[len(l.state.PolicyLog)-1000:]...)
	}
}

func (l *limiter) recordPolicyEvent(event policyEvent) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.appendPolicyEventLocked(event)
	_ = l.saveStateLocked()
	l.mu.Unlock()
}

func (l *limiter) dryRun() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cfg.DryRun
}

func (l *limiter) authDenyDecisionLocked(ctx endpointOverrideContext) (bool, string, string, bool) {
	for _, policy := range l.cfg.Policies {
		if !policy.Deny || !policy.matches(ctx) {
			continue
		}
		return true, policy.Name, policy.denyMessage(), l.cfg.DryRun
	}
	return false, "", "", l.cfg.DryRun
}

func (p policyRule) denyMessage() string {
	message := strings.TrimSpace(p.Message)
	if message != "" {
		return message
	}
	if strings.TrimSpace(p.Name) != "" {
		return "request denied by policy " + strings.TrimSpace(p.Name)
	}
	return "request denied by policy"
}

func dryRunAction(dryRunActionValue string, action string, dryRun bool) string {
	if dryRun {
		return dryRunActionValue
	}
	return action
}

func (l *limiter) endpointOverride(req pluginapi.RequestInterceptRequest) (string, string) {
	if l == nil {
		return "", ""
	}
	keyID := keyIDFromMetadata(req.Metadata)
	l.mu.Lock()
	defer l.mu.Unlock()
	var rules []endpointOverrideRule
	if keyID != "" {
		if rule, ok := l.configuredKeys[keyID]; ok {
			rules = append(rules, rule.EndpointOverrides...)
		} else if rule, ok := l.state.Keys[keyID]; ok {
			rules = append(rules, rule.EndpointOverrides...)
		}
	}
	rules = append(rules, l.cfg.EndpointOverrides...)
	ctx := endpointOverrideContext{
		KeyID:          keyID,
		Provider:       providerFromFormat(req.ToFormat),
		Model:          req.Model,
		RequestedModel: req.RequestedModel,
		SourceFormat:   req.SourceFormat,
		ToFormat:       req.ToFormat,
		RequestPath:    stringFromMetadata(req.Metadata, "request_path"),
	}
	for _, rule := range rules {
		if !rule.matches(ctx) {
			continue
		}
		if rule.Preserve {
			return "", rule.matchName()
		}
		forced := normalizeInterface(rule.ForceInterface)
		if forced == "" && len(rule.Interfaces) > 0 {
			forced = normalizeInterface(rule.Interfaces[0])
		}
		if forced == "" || forced == "passthrough" || forced == "preserve" {
			return "", rule.matchName()
		}
		return forced, rule.matchName()
	}
	return "", ""
}

func providerFromRequest(req pluginapi.FrontendAuthRequest) string {
	if provider := providerFromModel(requestedModel(req.Body)); provider != "" {
		return provider
	}
	path := normalizeEndpointPath(req.Path)
	switch {
	case strings.Contains(path, "/messages"):
		return "claude"
	case strings.Contains(path, "/responses") || strings.Contains(path, "/chat/completions"):
		return "openai"
	default:
		return ""
	}
}

func providerFromModel(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	for _, sep := range []string{"/", ":"} {
		if idx := strings.Index(model, sep); idx > 0 {
			provider := strings.TrimSpace(model[:idx])
			if provider != "" && provider != "models" {
				return provider
			}
		}
	}
	return ""
}

func keyPolicyAllowed(rule keyRule, model string, provider string, now time.Time) bool {
	if !modelAllowed(model, rule.AllowedModels) {
		return false
	}
	if strings.TrimSpace(model) != "" && stringListMatches(rule.DeniedModels, model) {
		return false
	}
	if len(rule.AllowedProviders) > 0 && (provider == "" || !stringListMatches(rule.AllowedProviders, provider)) {
		return false
	}
	if provider != "" && len(rule.DeniedProviders) > 0 && stringListMatches(rule.DeniedProviders, provider) {
		return false
	}
	return timeWindowsAllow(rule.TimeWindows, now)
}

func timeWindowsAllow(windows []timeWindowRule, now time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	allowWindows := 0
	allowed := false
	for _, window := range windows {
		matched := timeWindowMatches(window, now)
		if window.Deny {
			if matched {
				return false
			}
			continue
		}
		allowWindows++
		allowed = allowed || matched
	}
	return allowWindows == 0 || allowed
}

func timeWindowMatches(window timeWindowRule, now time.Time) bool {
	loc := time.UTC
	if tz := strings.TrimSpace(window.Timezone); tz != "" {
		if loaded, errLoad := time.LoadLocation(tz); errLoad == nil {
			loc = loaded
		}
	}
	local := now.In(loc)
	if len(window.Days) > 0 && !dayMatches(window.Days, local.Weekday()) {
		return false
	}
	start, okStart := parseClock(window.Start)
	end, okEnd := parseClock(window.End)
	if !okStart && !okEnd {
		return true
	}
	minute := local.Hour()*60 + local.Minute()
	if !okStart {
		return minute <= end
	}
	if !okEnd {
		return minute >= start
	}
	if start <= end {
		return minute >= start && minute <= end
	}
	return minute >= start || minute <= end
}

func dayMatches(patterns []string, day time.Weekday) bool {
	name := strings.ToLower(day.String())
	short := name
	if len(short) > 3 {
		short = short[:3]
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "*" || pattern == name || pattern == short {
			return true
		}
		if day >= time.Monday && day <= time.Friday && (pattern == "weekday" || pattern == "weekdays") {
			return true
		}
		if (day == time.Saturday || day == time.Sunday) && (pattern == "weekend" || pattern == "weekends") {
			return true
		}
	}
	return false
}

func parseClock(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return 0, false
	}
	hour, errHour := strconv.Atoi(parts[0])
	minute, errMinute := strconv.Atoi(parts[1])
	if errHour != nil || errMinute != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, false
	}
	return hour*60 + minute, true
}

func (l *limiter) matchingPolicies(ctx endpointOverrideContext) []policyRule {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	policies := append([]policyRule(nil), l.cfg.Policies...)
	l.mu.Unlock()
	matched := make([]policyRule, 0, len(policies))
	for _, policy := range policies {
		if policy.matches(ctx) {
			matched = append(matched, policy)
		}
	}
	return matched
}

func requestPolicyContext(req pluginapi.RequestInterceptRequest) endpointOverrideContext {
	return endpointOverrideContext{
		KeyID:          keyIDFromMetadata(req.Metadata),
		Provider:       providerFromFormat(req.ToFormat),
		Model:          req.Model,
		RequestedModel: req.RequestedModel,
		SourceFormat:   req.SourceFormat,
		ToFormat:       req.ToFormat,
		RequestPath:    stringFromMetadata(req.Metadata, "request_path"),
	}
}

func responsePolicyContext(req pluginapi.ResponseInterceptRequest) endpointOverrideContext {
	return endpointOverrideContext{
		KeyID:          keyIDFromMetadata(req.Metadata),
		Model:          req.Model,
		RequestedModel: req.RequestedModel,
		SourceFormat:   req.SourceFormat,
		RequestPath:    stringFromMetadata(req.Metadata, "request_path"),
	}
}

type endpointOverrideContext struct {
	KeyID          string
	Provider       string
	Model          string
	RequestedModel string
	SourceFormat   string
	ToFormat       string
	RequestPath    string
}

func (r endpointOverrideRule) matches(ctx endpointOverrideContext) bool {
	if !stringListMatches(r.Keys, ctx.KeyID) {
		return false
	}
	if !stringListMatches(r.Providers, ctx.Provider) {
		return false
	}
	if !stringListMatches(r.Models, ctx.Model) {
		return false
	}
	if !stringListMatches(r.RequestedModels, ctx.RequestedModel) {
		return false
	}
	if !stringListMatches(r.SourceFormats, ctx.SourceFormat) {
		return false
	}
	if !stringListMatches(r.ToFormats, ctx.ToFormat) {
		return false
	}
	if !pathListMatches(r.RequestPaths, ctx.RequestPath) {
		return false
	}
	return true
}

func (p policyRule) matches(ctx endpointOverrideContext) bool {
	if !stringListMatches(p.Match.Keys, ctx.KeyID) {
		return false
	}
	if !stringListMatches(p.Match.Providers, ctx.Provider) {
		return false
	}
	if !stringListMatches(p.Match.Models, ctx.Model) {
		return false
	}
	if !stringListMatches(p.Match.RequestedModels, ctx.RequestedModel) {
		return false
	}
	if !stringListMatches(p.Match.SourceFormats, ctx.SourceFormat) {
		return false
	}
	if !stringListMatches(p.Match.ToFormats, ctx.ToFormat) {
		return false
	}
	if !pathListMatches(p.Match.RequestPaths, ctx.RequestPath) {
		return false
	}
	return true
}

func applyRequestPolicy(action requestPolicyAction, headers http.Header, clearHeaders *[]string, body *[]byte) (bool, error) {
	changed := applyHeaderPolicy(action.SetHeaders, action.DeleteHeaders, headers, clearHeaders, protectedRequestHeaders)
	if strings.TrimSpace(action.SetModel) != "" {
		if errSet := setJSONPath(body, "model", strings.TrimSpace(action.SetModel)); errSet != nil {
			return changed, errSet
		}
		changed = true
	}
	if strings.TrimSpace(action.SetServiceTier) != "" {
		if errSet := setJSONPath(body, "service_tier", strings.TrimSpace(action.SetServiceTier)); errSet != nil {
			return changed, errSet
		}
		changed = true
	}
	if action.MaxTokens != nil {
		updated, errClamp := clampJSONInt(body, []string{"max_tokens", "max_completion_tokens"}, *action.MaxTokens)
		if errClamp != nil {
			return changed, errClamp
		}
		changed = changed || updated
	}
	if action.Temperature != nil {
		updated, errClamp := clampJSONFloat(body, "temperature", *action.Temperature)
		if errClamp != nil {
			return changed, errClamp
		}
		changed = changed || updated
	}
	if len(action.ReasoningEffort.Deny) > 0 || strings.TrimSpace(action.ReasoningEffort.Replace) != "" {
		updated, errReasoning := applyReasoningEffortPolicy(body, action.ReasoningEffort)
		if errReasoning != nil {
			return changed, errReasoning
		}
		changed = changed || updated
	}
	updated, errJSON := applyJSONPolicy(action.SetJSON, action.DeleteJSON, body)
	return changed || updated, errJSON
}

func requestPolicyConfigured(action requestPolicyAction) bool {
	return len(action.SetHeaders) > 0 || len(action.DeleteHeaders) > 0 || len(action.SetJSON) > 0 || len(action.DeleteJSON) > 0 || strings.TrimSpace(action.SetModel) != "" || strings.TrimSpace(action.SetServiceTier) != "" || action.MaxTokens != nil || action.Temperature != nil || len(action.ReasoningEffort.Deny) > 0 || strings.TrimSpace(action.ReasoningEffort.Replace) != ""
}

func applyResponsePolicy(action responsePolicyAction, headers http.Header, clearHeaders *[]string, body *[]byte) (bool, error) {
	changed := applyHeaderPolicy(action.SetHeaders, action.DeleteHeaders, headers, clearHeaders, protectedResponseHeaders)
	updated, errJSON := applyJSONPolicy(action.SetJSON, action.DeleteJSON, body)
	return changed || updated, errJSON
}

func responsePolicyConfigured(action responsePolicyAction) bool {
	return len(action.SetHeaders) > 0 || len(action.DeleteHeaders) > 0 || len(action.SetJSON) > 0 || len(action.DeleteJSON) > 0
}

func errorResponseConfigured(rule errorResponseRule) bool {
	return rule.StatusCode > 0 || strings.TrimSpace(rule.Message) != "" || strings.TrimSpace(rule.Body) != "" || len(rule.JSON) > 0 || len(rule.SetHeaders) > 0 || rule.HideUpstream
}

func applyCustomErrorResponse(rule errorResponseRule, headers *http.Header, clearHeaders *[]string, body *[]byte) bool {
	if !errorResponseConfigured(rule) || !upstreamBodyLooksLikeError(*body) {
		return false
	}
	if headers == nil {
		return false
	}
	for name, value := range rule.SetHeaders {
		name = strings.TrimSpace(name)
		if name == "" || protectedHeader(name, protectedResponseHeaders) {
			continue
		}
		headers.Set(name, value)
	}
	if len(rule.JSON) > 0 {
		payload := cloneAnyMap(rule.JSON)
		if _, exists := payload["error"]; !exists && strings.TrimSpace(rule.Message) != "" {
			payload["error"] = map[string]any{"message": strings.TrimSpace(rule.Message), "type": "policy_hub_error"}
		}
		if raw, errMarshal := json.Marshal(payload); errMarshal == nil {
			*body = raw
			headers.Set("Content-Type", "application/json; charset=utf-8")
			return true
		}
	}
	message := strings.TrimSpace(rule.Body)
	if message == "" {
		message = strings.TrimSpace(rule.Message)
	}
	if message == "" {
		message = "The upstream provider returned an error. Try a different model or contact the API administrator."
	}
	*body = []byte(`{"error":{"message":` + strconv.Quote(message) + `,"type":"policy_hub_error"}}`)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	return true
}

func upstreamBodyLooksLikeError(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || len(trimmed) > maxAuthModelBodyBytes {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(trimmed, &payload) != nil {
		text := strings.ToLower(string(trimmed))
		return strings.Contains(text, "error") || strings.Contains(text, "exception") || strings.Contains(text, "rate limit")
	}
	if _, ok := payload["error"]; ok {
		return true
	}
	if _, ok := payload["errors"]; ok {
		return true
	}
	status := strings.ToLower(stringFromAny(payload["status"]))
	return status == "error" || status == "failed"
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func applyHeaderPolicy(setHeaders map[string]string, deleteHeaders []string, headers http.Header, clearHeaders *[]string, protected map[string]struct{}) bool {
	changed := false
	for name, value := range setHeaders {
		name = strings.TrimSpace(name)
		if name == "" || protectedHeader(name, protected) {
			continue
		}
		headers.Set(name, value)
		changed = true
	}
	for _, name := range deleteHeaders {
		name = strings.TrimSpace(name)
		if name == "" || protectedHeader(name, protected) {
			continue
		}
		*clearHeaders = append(*clearHeaders, name)
		changed = true
	}
	return changed
}

func protectedHeader(name string, protected map[string]struct{}) bool {
	if len(protected) == 0 {
		return false
	}
	_, ok := protected[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func applyJSONPolicy(setValues map[string]any, deletePaths []string, body *[]byte) (bool, error) {
	changed := false
	for path, value := range setValues {
		if errSet := setJSONPath(body, path, value); errSet != nil {
			return changed, errSet
		}
		changed = true
	}
	for _, path := range deletePaths {
		updated, errDelete := deleteJSONPath(body, path)
		if errDelete != nil {
			return changed, errDelete
		}
		changed = changed || updated
	}
	return changed, nil
}

func setJSONPath(body *[]byte, path string, value any) error {
	payload := map[string]any{}
	if len(bytes.TrimSpace(*body)) > 0 {
		if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return nil
	}
	current := payload
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok || next == nil {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
	return marshalJSONBody(body, payload)
}

func deleteJSONPath(body *[]byte, path string) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return false, nil
	}
	current := payload
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok || next == nil {
			return false, nil
		}
		current = next
	}
	last := parts[len(parts)-1]
	if _, exists := current[last]; !exists {
		return false, nil
	}
	delete(current, last)
	return true, marshalJSONBody(body, payload)
}

func clampJSONInt(body *[]byte, paths []string, clamp intClamp) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	changed := false
	for _, path := range paths {
		value, ok := jsonPathValue(payload, path)
		if !ok {
			continue
		}
		number, okNumber := numberToFloat64(value)
		if !okNumber {
			continue
		}
		clamped := int64(number)
		if clamp.Min > 0 && clamped < clamp.Min {
			clamped = clamp.Min
		}
		if clamp.Max > 0 && clamped > clamp.Max {
			clamped = clamp.Max
		}
		if float64(clamped) != number {
			if errSet := setJSONValue(payload, path, clamped); errSet != nil {
				return changed, errSet
			}
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	return true, marshalJSONBody(body, payload)
}

func clampJSONFloat(body *[]byte, path string, clamp floatClamp) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	value, ok := jsonPathValue(payload, path)
	if !ok {
		return false, nil
	}
	number, okNumber := numberToFloat64(value)
	if !okNumber {
		return false, nil
	}
	clamped := number
	if clamp.Min > 0 && clamped < clamp.Min {
		clamped = clamp.Min
	}
	if clamp.Max > 0 && clamped > clamp.Max {
		clamped = clamp.Max
	}
	if clamped == number {
		return false, nil
	}
	if errSet := setJSONValue(payload, path, clamped); errSet != nil {
		return false, errSet
	}
	return true, marshalJSONBody(body, payload)
}

func applyReasoningEffortPolicy(body *[]byte, policy reasoningEffortPolicy) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	value, ok := jsonPathValue(payload, "reasoning.effort")
	if !ok {
		value, ok = jsonPathValue(payload, "thinking.effort")
	}
	if !ok {
		return false, nil
	}
	effort := strings.ToLower(strings.TrimSpace(stringFromAny(value)))
	if effort == "" || !stringListMatches(policy.Deny, effort) {
		return false, nil
	}
	replacement := strings.TrimSpace(policy.Replace)
	if replacement == "" {
		replacement = "medium"
	}
	if _, exists := jsonPathValue(payload, "reasoning.effort"); exists {
		if errSet := setJSONValue(payload, "reasoning.effort", replacement); errSet != nil {
			return false, errSet
		}
	} else if errSet := setJSONValue(payload, "thinking.effort", replacement); errSet != nil {
		return false, errSet
	}
	return true, marshalJSONBody(body, payload)
}

func jsonPathParts(path string) []string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return nil
	}
	rawParts := strings.Split(path, ".")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func jsonPathValue(payload map[string]any, path string) (any, bool) {
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return nil, false
	}
	var current any = payload
	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func setJSONValue(payload map[string]any, path string, value any) error {
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return nil
	}
	current := payload
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok || next == nil {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
	return nil
}

func marshalJSONBody(body *[]byte, payload map[string]any) error {
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return errMarshal
	}
	*body = raw
	return nil
}

func numberToFloat64(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case json.Number:
		parsed, errParse := typed.Float64()
		return parsed, errParse == nil
	default:
		return 0, false
	}
}

func (r endpointOverrideRule) matchName() string {
	name := strings.TrimSpace(r.Name)
	if name != "" {
		return name
	}
	forced := normalizeInterface(r.ForceInterface)
	if forced != "" {
		return forced
	}
	if len(r.Interfaces) > 0 {
		return normalizeInterface(r.Interfaces[0])
	}
	return "preserve"
}

func providerFromFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "openai", "openai-response":
		return "openai"
	case "claude":
		return "claude"
	case "gemini":
		return "gemini"
	case "codex":
		return "codex"
	case "antigravity":
		return "antigravity"
	default:
		return strings.ToLower(strings.TrimSpace(format))
	}
}

func normalizeInterface(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "/v1/")
	value = strings.TrimPrefix(value, "/")
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, "/", "_")
	switch value {
	case "", "passthrough", "preserve":
		return value
	case "chat", "chat_completions", "chat_complete", "chat_completion", "completions":
		return "chat_completions"
	case "message", "messages":
		return "messages"
	case "response", "responses":
		return "responses"
	case "responses_compact", "response_compact":
		return "responses_compact"
	default:
		return value
	}
}

func keyIDFromMetadata(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	if access, ok := metadata["accessMetadata"].(map[string]any); ok {
		if keyID := stringFromAny(access["key_id"]); keyID != "" {
			return keyID
		}
	}
	if access, ok := metadata["access_metadata"].(map[string]any); ok {
		if keyID := stringFromAny(access["key_id"]); keyID != "" {
			return keyID
		}
	}
	if keyID := stringFromAny(metadata["key_id"]); keyID != "" {
		return keyID
	}
	return ""
}

func stringFromMetadata(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	return stringFromAny(metadata[key])
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return ""
	}
}

func stringListMatches(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	value = strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == value || wildcardMatch(pattern, value) {
			return true
		}
	}
	return false
}

func pathListMatches(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	value = normalizeEndpointPath(value)
	for _, pattern := range patterns {
		pattern = normalizeEndpointPath(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == value || strings.HasSuffix(value, pattern) || wildcardMatch(pattern, value) {
			return true
		}
	}
	return false
}

func normalizeEndpointPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimPrefix(path, "/v1")
	if path == "" {
		return "/"
	}
	return path
}

func wildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	return strings.HasSuffix(value[pos:], last)
}

func (l *limiter) listKeysLocked() []keyListItem {
	keys := make([]keyListItem, 0, len(l.configuredKeys)+len(l.state.Keys))
	for _, rule := range l.configuredKeys {
		if override, exists := l.state.Keys[rule.ID]; exists {
			override.Source = "override"
			override.KeyHash = maskHash(override.KeyHash)
			override.Key = ""
			keys = append(keys, keyListItem{keyRule: override, Usage: l.state.Usage[override.ID]})
			continue
		}
		rule.Source = "config"
		rule.KeyHash = maskHash(rule.KeyHash)
		rule.Key = ""
		keys = append(keys, keyListItem{keyRule: rule, Usage: l.state.Usage[rule.ID]})
	}
	for _, rule := range l.state.Keys {
		if _, exists := l.configuredKeys[rule.ID]; exists {
			continue
		}
		rule.Source = "managed"
		rule.KeyHash = maskHash(rule.KeyHash)
		rule.Key = ""
		keys = append(keys, keyListItem{keyRule: rule, Usage: l.state.Usage[rule.ID]})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	return keys
}

func (l *limiter) saveStateLocked() error {
	l.state.UpdatedAt = time.Now().UTC()
	return saveState(l.cfg.StoragePath, l.state)
}

func normalizeKeyRule(rule keyRule, cfg pluginConfig, source string) (keyRule, bool) {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Tenant = strings.TrimSpace(rule.Tenant)
	rule.Plan = strings.TrimSpace(rule.Plan)
	rule.Key = strings.TrimSpace(rule.Key)
	rule.KeyHash = normalizeHash(rule.KeyHash)
	rule.ExpiresAt = strings.TrimSpace(rule.ExpiresAt)
	rule.Source = source
	if rule.KeyHash == "" && rule.Key != "" {
		rule.KeyHash = hashAPIKey(rule.Key)
	}
	if !validSHA256Hash(rule.KeyHash) {
		return keyRule{}, false
	}
	if rule.Metadata != nil {
		for key := range rule.Metadata {
			if reservedAuthMetadataKey(key) {
				delete(rule.Metadata, key)
			}
		}
	}
	rule.AllowedModels = uniqueNonEmptyStrings(rule.AllowedModels)
	rule.DeniedModels = uniqueNonEmptyStrings(rule.DeniedModels)
	rule.AllowedProviders = uniqueNonEmptyStrings(rule.AllowedProviders)
	rule.DeniedProviders = uniqueNonEmptyStrings(rule.DeniedProviders)
	if rule.ID == "" && rule.KeyHash != "" {
		rule.ID = "key_" + strings.TrimPrefix(rule.KeyHash, "sha256:")[:12]
	}
	if rule.ID == "" || rule.KeyHash == "" {
		return keyRule{}, false
	}
	if rule.DailyTokenLimit == 0 {
		rule.DailyTokenLimit = cfg.DefaultDailyTokenLimit
	}
	if rule.MonthlyTokenLimit == 0 {
		rule.MonthlyTokenLimit = cfg.DefaultMonthlyTokenLimit
	}
	if rule.TotalTokenLimit == 0 {
		rule.TotalTokenLimit = cfg.DefaultTotalTokenLimit
	}
	if rule.RequestLimitPerMinute == 0 {
		rule.RequestLimitPerMinute = cfg.DefaultRequestLimitPerMinute
	}
	if len(rule.AllowedModels) == 0 && len(cfg.DefaultAllowedModels) > 0 {
		rule.AllowedModels = append([]string(nil), cfg.DefaultAllowedModels...)
	}
	for idx := range rule.TimeWindows {
		rule.TimeWindows[idx].Name = strings.TrimSpace(rule.TimeWindows[idx].Name)
		rule.TimeWindows[idx].Timezone = strings.TrimSpace(rule.TimeWindows[idx].Timezone)
		rule.TimeWindows[idx].Start = strings.TrimSpace(rule.TimeWindows[idx].Start)
		rule.TimeWindows[idx].End = strings.TrimSpace(rule.TimeWindows[idx].End)
		rule.TimeWindows[idx].Days = uniqueNonEmptyStrings(rule.TimeWindows[idx].Days)
	}
	rule.ErrorResponse.Name = strings.TrimSpace(rule.ErrorResponse.Name)
	rule.ErrorResponse.Message = strings.TrimSpace(rule.ErrorResponse.Message)
	rule.ErrorResponse.Body = strings.TrimSpace(rule.ErrorResponse.Body)
	if rule.ErrorResponse.StatusCode < 0 || rule.ErrorResponse.StatusCode > 599 {
		rule.ErrorResponse.StatusCode = 0
	}
	for idx, status := range rule.ErrorResponse.UpstreamStatuses {
		if status < 100 || status > 599 {
			rule.ErrorResponse.UpstreamStatuses[idx] = 0
		}
	}
	rule.Key = ""
	return rule, true
}

func (r keyRule) usable(now time.Time) bool {
	if r.Disabled {
		return false
	}
	if r.ExpiresAt == "" {
		return true
	}
	expiresAt, errParse := time.Parse(time.RFC3339, r.ExpiresAt)
	if errParse != nil {
		return false
	}
	return now.Before(expiresAt)
}

func withinQuota(rule keyRule, usage *usageCounter, now time.Time) bool {
	if usage == nil {
		return true
	}
	if rule.TotalTokenLimit > 0 && usage.TotalTokens >= rule.TotalTokenLimit {
		return false
	}
	if rule.HourlyTokenLimit > 0 && usage.HourlyTokens[hourKey(now)] >= rule.HourlyTokenLimit {
		return false
	}
	if rule.DailyTokenLimit > 0 && usage.DailyTokens[dayKey(now)] >= rule.DailyTokenLimit {
		return false
	}
	if rule.MonthlyTokenLimit > 0 && usage.MonthlyTokens[monthKey(now)] >= rule.MonthlyTokenLimit {
		return false
	}
	return true
}

func modelAllowed(model string, allowed []string) bool {
	if len(allowed) == 0 || strings.TrimSpace(model) == "" {
		return true
	}
	model = strings.ToLower(strings.TrimSpace(model))
	for _, pattern := range allowed {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == model {
			return true
		}
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(model, strings.TrimSuffix(pattern, "*")) {
			return true
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(model, strings.TrimPrefix(pattern, "*")) {
			return true
		}
	}
	return false
}

func requestedModel(body []byte) string {
	if len(body) > maxAuthModelBodyBytes {
		return ""
	}
	var payload map[string]any
	if len(body) == 0 || json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if model, ok := payload["model"].(string); ok {
		return strings.TrimSpace(model)
	}
	return ""
}

func extractCredential(headers http.Header, query map[string][]string) (string, string) {
	candidates := []struct {
		value  string
		source string
	}{
		{extractBearerToken(headers.Get("Authorization")), "authorization"},
		{headers.Get("X-Goog-Api-Key"), "x-goog-api-key"},
		{headers.Get("X-Api-Key"), "x-api-key"},
		{firstQuery(query, "key"), "query-key"},
		{firstQuery(query, "auth_token"), "query-auth-token"},
	}
	for _, candidate := range candidates {
		value := strings.TrimSpace(candidate.value)
		if value != "" {
			return value, candidate.source
		}
	}
	return "", ""
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return header
	}
	return strings.TrimSpace(parts[1])
}

func firstQuery(query map[string][]string, key string) string {
	values := query[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func pruneRequestMinutes(usage *usageCounter, cutoff time.Time) {
	if usage == nil || len(usage.RequestsByMinute) == 0 {
		return
	}
	for key := range usage.RequestsByMinute {
		parsed, errParse := time.Parse("2006-01-02T15:04Z", key)
		if errParse == nil && parsed.Before(cutoff) {
			delete(usage.RequestsByMinute, key)
		}
	}
}

func loadState(path string) (persistedState, error) {
	state := persistedState{Keys: map[string]keyRule{}, Usage: map[string]*usageCounter{}}
	path = strings.TrimSpace(path)
	if path == "" {
		return state, nil
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		if os.IsNotExist(errRead) {
			return state, nil
		}
		return state, errRead
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return state, nil
	}
	if errUnmarshal := json.Unmarshal(raw, &state); errUnmarshal != nil {
		return state, errUnmarshal
	}
	if state.Keys == nil {
		state.Keys = map[string]keyRule{}
	}
	if state.Usage == nil {
		state.Usage = map[string]*usageCounter{}
	}
	if state.PolicyLog == nil {
		state.PolicyLog = []policyEvent{}
	}
	if state.Policies == nil {
		state.Policies = map[string]*usageCounter{}
	}
	if state.Active == nil {
		state.Active = map[string]int{}
	}
	return state, nil
}

func saveState(path string, state persistedState) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if errMkdir := os.MkdirAll(dir, 0o755); errMkdir != nil {
			return errMkdir
		}
	}
	raw, errMarshal := json.MarshalIndent(state, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	tmpPath := path + ".tmp"
	if errWrite := os.WriteFile(tmpPath, raw, 0o600); errWrite != nil {
		return errWrite
	}
	return os.Rename(tmpPath, path)
}

func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashMatches(storedHash string, candidateHash string) bool {
	storedHash = normalizeHash(storedHash)
	candidateHash = normalizeHash(candidateHash)
	if !validSHA256Hash(storedHash) || !validSHA256Hash(candidateHash) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(candidateHash)) == 1
}

func normalizeHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ""
	}
	if strings.HasPrefix(hash, "sha256:") {
		return strings.ToLower(hash)
	}
	if len(hash) == 64 {
		return "sha256:" + strings.ToLower(hash)
	}
	return hash
}

func validSHA256Hash(hash string) bool {
	hash = strings.TrimPrefix(strings.TrimSpace(hash), "sha256:")
	if len(hash) != 64 {
		return false
	}
	_, errDecode := hex.DecodeString(hash)
	return errDecode == nil
}

func maskHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 20 {
		return hash
	}
	return hash[:16] + "..." + hash[len(hash)-8:]
}

func dayKey(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

func hourKey(t time.Time) string {
	return t.UTC().Format("2006-01-02T15Z")
}

func monthKey(t time.Time) string {
	return t.UTC().Format("2006-01")
}

func policyRequestDayKey(t time.Time) string {
	return "requests:" + dayKey(t)
}

func policyRequestMonthKey(t time.Time) string {
	return "requests:" + monthKey(t)
}

func minuteKey(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04Z")
}

func randomHex(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, errRead := rand.Read(buf); errRead != nil {
		return "", errRead
	}
	return hex.EncodeToString(buf), nil
}

func jsonResponse(status int, v any) pluginapi.ManagementResponse {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		status = http.StatusInternalServerError
		raw = []byte(`{"error":"failed to encode response"}`)
	}
	return pluginapi.ManagementResponse{StatusCode: status, Headers: jsonHeaders(), Body: raw}
}

func jsonHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}
}

func htmlHeaders() http.Header {
	return http.Header{
		"Content-Type":            []string{"text/html; charset=utf-8"},
		"X-Content-Type-Options":  []string{"nosniff"},
		"Referrer-Policy":         []string{"no-referrer"},
		"Content-Security-Policy": []string{"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"},
	}
}

func finalStatusHTML() string {
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CPA Policy Hub</title><style>
:root{color-scheme:dark;--bg:#020617;--panel:#0f172a;--card:#111827;--line:#334155;--text:#e5e7eb;--muted:#94a3b8;--blue:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444}*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(135deg,#020617,#111827 55%,#172554);color:var(--text)}header{padding:26px 32px 16px;border-bottom:1px solid #ffffff14}h1{margin:0;font-size:28px}h2{margin:0 0 12px}.muted{color:var(--muted)}main{padding:22px 32px 42px;display:grid;gap:16px}.card{background:rgba(15,23,42,.9);border:1px solid rgba(148,163,184,.24);border-radius:18px;box-shadow:0 18px 50px #0006;padding:18px}.grid{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:14px}.split{display:grid;grid-template-columns:minmax(540px,1.2fr) minmax(420px,.8fr);gap:16px}.bar{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:end}.stat{font-size:26px;font-weight:800}.pill{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:5px 10px;color:var(--muted)}.ok{color:var(--ok);border-color:#22c55e88}.warn{color:var(--warn);border-color:#f59e0b88}.bad{color:var(--bad);border-color:#ef444488}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tab.active{background:#1d4ed8}button,input,select,textarea{font:inherit;border:1px solid var(--line);border-radius:10px;background:#020617;color:var(--text);padding:9px 11px}button{cursor:pointer;background:#0f172a}button.primary{background:linear-gradient(135deg,#0284c7,#2563eb);border:0;font-weight:700}button.danger{border-color:#ef444488;color:#fecaca}.actions{display:flex;gap:8px;flex-wrap:wrap}.form{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.full{grid-column:1/-1}label{display:grid;gap:5px;color:var(--muted)}label span{font-size:12px;text-transform:uppercase;letter-spacing:.04em}textarea{width:100%;min-height:112px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #94a3b82d;padding:9px;text-align:left;vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase}.hidden{display:none}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.notice{border-left:4px solid var(--blue);padding:10px 12px;background:#38bdf817;border-radius:12px}.toast{position:fixed;right:20px;bottom:20px;max-width:560px;background:#020617;border:1px solid var(--line);border-radius:14px;padding:12px 14px;box-shadow:0 20px 60px #0008}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:1100px){.grid,.split,.bar,.form,.two{grid-template-columns:1fr}}
</style></head><body><header><h1>CPA Policy Hub</h1><div class="muted">Final server UI: keys, limits, overrides, usage, state backup and config snippets.</div></header><main>
<section class="card bar"><label><span>Management key</span><input id="mk" type="password" autocomplete="off" placeholder="Paste CPA / CPAMC management key"></label><div class="actions"><button class="primary" onclick="connect()">Connect</button><button onclick="clearKey()">Clear</button><button onclick="loadAll()">Refresh</button></div></section>
<section class="grid"><div class="card"><div class="muted">Traffic</div><div id="sTraffic" class="stat">-</div></div><div class="card"><div class="muted">Configured</div><div id="sConfigured" class="stat">-</div></div><div class="card"><div class="muted">Managed</div><div id="sManaged" class="stat">-</div></div><div class="card"><div class="muted">Policies</div><div id="sPolicies" class="stat">-</div></div></section>
<section class="card"><div class="tabs"><button class="tab active" data-tab="keys">Keys</button><button class="tab" data-tab="usage">Usage</button><button class="tab" data-tab="events">Events</button><button class="tab" data-tab="state">Backup</button><button class="tab" data-tab="config">Config</button></div></section>
<section id="keys" class="view split"><div class="card"><div class="bar"><div><h2>API Keys</h2><div class="muted">Imported CPA keys can be overridden here. Existing secret material is never shown.</div></div><button onclick="loadKeys()">Refresh</button></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>ID</th><th>Source</th><th>Limits</th><th>Policy</th><th>Usage</th><th></th></tr></thead><tbody id="keyRows"><tr><td colspan="7" class="muted">Connect first.</td></tr></tbody></table></div></div>
<div class="card"><h2 id="formTitle">Create / edit key</h2><div class="form"><label><span>ID</span><input id="fId" placeholder="auto for new key"></label><label><span>Name</span><input id="fName" placeholder="Team A"></label><label class="full"><span>Plain API key</span><input id="fKey" placeholder="Only for create or replacing key material"></label><label><span>Daily tokens</span><input id="fDaily" type="number" min="0"></label><label><span>Monthly tokens</span><input id="fMonthly" type="number" min="0"></label><label><span>Total tokens</span><input id="fTotal" type="number" min="0"></label><label><span>Hourly tokens</span><input id="fHourlyTokens" type="number" min="0"></label><label><span>RPM</span><input id="fRpm" type="number" min="0"></label><label><span>Hourly requests</span><input id="fHourlyRequests" type="number" min="0"></label><label class="full"><span>Allowed models</span><input id="fModels" placeholder="*, openai/*, gpt-*"></label><label class="full"><span>Denied models</span><input id="fDeniedModels" placeholder="gpt-5-pro, *expensive*"></label><label><span>Allowed providers</span><input id="fAllowedProviders" placeholder="openai, claude"></label><label><span>Denied providers</span><input id="fDeniedProviders" placeholder="gemini"></label><label><span>Tenant</span><input id="fTenant"></label><label><span>Plan</span><input id="fPlan"></label><label><span>Disabled</span><select id="fDisabled"><option value="false">No</option><option value="true">Yes</option></select></label><label><span>Expires at</span><input id="fExpires" placeholder="2026-12-31T00:00:00Z"></label><label class="full"><span>Time windows JSON</span><textarea id="fWindows" placeholder='[{"timezone":"Asia/Shanghai","days":["weekday"],"start":"09:00","end":"23:00"}]'></textarea></label><label class="full"><span>Request override JSON</span><textarea id="fRequest" placeholder='{"set_model":"real-upstream-model","set_headers":{"X-Team":"team-a"}}'></textarea></label><label class="full"><span>Response override JSON</span><textarea id="fResponse" placeholder='{"set_headers":{"X-Policy-Hub":"team-a"}}'></textarea></label><label class="full"><span>Error response JSON</span><textarea id="fError" placeholder='{"message":"Upstream returned an error. Try another model."}'></textarea></label></div><div class="actions" style="margin-top:14px"><button class="primary" onclick="saveKey()">Save runtime override</button><button onclick="newKey()">New</button><button class="danger" onclick="deleteKey()">Delete override</button></div><div class="notice" style="margin-top:12px">Save writes to state file, not CPA config.yaml. Restart is usually not required for runtime overrides.</div><pre id="createdSecret" class="mono muted"></pre></div></section>
<section id="usage" class="view card hidden"><div class="bar"><h2>Usage</h2><button onclick="loadUsage()">Refresh</button></div><pre id="usageBox" class="mono">Connect first.</pre></section>
<section id="events" class="view card hidden"><div class="bar"><h2>Events / Policy log</h2><button onclick="loadEvents()">Refresh</button></div><pre id="eventsBox" class="mono">Connect first.</pre></section>
<section id="state" class="view card hidden"><h2>Backup / Restore</h2><div class="actions"><button onclick="exportState()">Export state</button><button onclick="importState(false)">Import merge</button><button class="danger" onclick="importState(true)">Import replace</button></div><textarea id="stateText" style="min-height:320px"></textarea></section>
<section id="config" class="view card hidden"><h2>Server config snippets</h2><p class="muted">Copy into CPA config.yaml. UI does not rewrite config.yaml.</p><div class="actions"><button onclick="buildSafeConfig()">Safe</button><button onclick="buildTakeoverConfig()">Takeover</button><button onclick="buildPolicyConfig()">Rewrite policy</button></div><textarea id="configText" style="min-height:360px"></textarea></section>
</main><div id="toast" class="toast hidden"></div><script>
const api='/v0/management/plugins/cpa-policy-hub';let managementKey='';let keys=[];const $=id=>document.getElementById(id);function toast(m,bad){const t=$('toast');t.textContent=m;t.className='toast '+(bad?'bad':'ok');setTimeout(()=>t.className='toast hidden',4500)}function pretty(v){return JSON.stringify(v,null,2)}function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}function escAttr(s){return esc(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;')}function csv(s){return String(s||'').split(',').map(x=>x.trim()).filter(Boolean)}function num(id){const v=$(id).value;return v===''?0:Number(v)}function parseJSON(id,fallback){const v=$(id).value.trim();if(!v)return fallback;return JSON.parse(v)}function setJSON(id,v){$(id).value=v&&Object.keys(v).length?pretty(v):''}async function call(path,opt){if(!managementKey)throw new Error('management key required');opt=opt||{};opt.headers=Object.assign({'Authorization':'Bearer '+managementKey},opt.headers||{});if(opt.body&&!opt.headers['Content-Type'])opt.headers['Content-Type']='application/json';const r=await fetch(api+path,opt);const text=await r.text();let d;try{d=JSON.parse(text)}catch(e){throw new Error(text||r.status)}if(!r.ok)throw new Error(d.error||text||r.status);return d}
function connect(){managementKey=$('mk').value.trim();if(!managementKey){toast('Paste management key first',true);return}loadAll()}function clearKey(){managementKey='';$('mk').value='';keys=[];renderKeys();toast('Cleared')}document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('hidden',v.id!==b.dataset.tab));});
async function loadAll(){try{await loadStatus();await loadKeys();await loadUsage();await loadEvents()}catch(e){toast(String(e.message||e),true)}}async function loadStatus(){const s=await call('/status');$('sTraffic').textContent=s.traffic_enabled?'Enabled':'Off';$('sTraffic').className='stat '+(s.traffic_enabled?'ok':'warn');$('sConfigured').textContent=s.configured_keys||0;$('sManaged').textContent=s.managed_keys||0;$('sPolicies').textContent=s.policies||0;if(s.config_load_error)toast('Config load error: '+s.config_load_error,true)}async function loadKeys(){const d=await call('/keys');keys=d.keys||[];renderKeys()}function renderKeys(){const tb=$('keyRows');if(!keys.length){tb.innerHTML='<tr><td colspan="7" class="muted">No keys loaded.</td></tr>';return}tb.innerHTML=keys.map(k=>{const u=k.usage||{};const limits='d '+(k.daily_token_limit||0)+' / hTok '+(k.hourly_token_limit||0)+' / rpm '+(k.request_limit_per_minute||0)+' / hReq '+(k.hourly_request_limit||0);const pol='models '+esc((k.allowed_models||[]).join(','))+'<br>providers '+esc((k.allowed_providers||[]).join(','));const usage='tokens '+(u.total_tokens||0)+' / req '+(u.requests||0);return '<tr><td>'+esc(k.name||'-')+'</td><td class="mono">'+esc(k.id)+'</td><td><span class="pill '+(k.source==='config'?'warn':'ok')+'">'+esc(k.source||'managed')+'</span></td><td>'+esc(limits)+'</td><td>'+pol+'</td><td>'+esc(usage)+'</td><td><button onclick="editKey(\''+escAttr(k.id)+'\')">Edit</button></td></tr>'}).join('')}function editKey(id){const k=keys.find(x=>x.id===id);if(!k)return;$('formTitle').textContent='Edit '+(k.name||id);$('fId').value=k.id||'';$('fName').value=k.name||'';$('fKey').value='';$('fDaily').value=k.daily_token_limit||0;$('fMonthly').value=k.monthly_token_limit||0;$('fTotal').value=k.total_token_limit||0;$('fHourlyTokens').value=k.hourly_token_limit||0;$('fRpm').value=k.request_limit_per_minute||0;$('fHourlyRequests').value=k.hourly_request_limit||0;$('fModels').value=(k.allowed_models||[]).join(', ');$('fDeniedModels').value=(k.denied_models||[]).join(', ');$('fAllowedProviders').value=(k.allowed_providers||[]).join(', ');$('fDeniedProviders').value=(k.denied_providers||[]).join(', ');$('fTenant').value=k.tenant||'';$('fPlan').value=k.plan||'';$('fDisabled').value=k.disabled?'true':'false';$('fExpires').value=k.expires_at||'';$('fWindows').value=(k.time_windows||[]).length?pretty(k.time_windows):'';setJSON('fRequest',k.request||{});setJSON('fResponse',k.response||{});setJSON('fError',k.error_response||{});$('createdSecret').textContent=''}function newKey(){$('formTitle').textContent='Create managed key';['fId','fName','fKey','fDaily','fMonthly','fTotal','fHourlyTokens','fRpm','fHourlyRequests','fModels','fDeniedModels','fAllowedProviders','fDeniedProviders','fTenant','fPlan','fExpires','fWindows','fRequest','fResponse','fError'].forEach(id=>$(id).value='');$('fDisabled').value='false';$('createdSecret').textContent=''}async function saveKey(){try{const body={id:$('fId').value.trim(),name:$('fName').value.trim(),key:$('fKey').value.trim(),daily_token_limit:num('fDaily'),monthly_token_limit:num('fMonthly'),total_token_limit:num('fTotal'),hourly_token_limit:num('fHourlyTokens'),request_limit_per_minute:num('fRpm'),hourly_request_limit:num('fHourlyRequests'),allowed_models:csv($('fModels').value),denied_models:csv($('fDeniedModels').value),allowed_providers:csv($('fAllowedProviders').value),denied_providers:csv($('fDeniedProviders').value),tenant:$('fTenant').value.trim(),plan:$('fPlan').value.trim(),disabled:$('fDisabled').value==='true',expires_at:$('fExpires').value.trim(),time_windows:parseJSON('fWindows',[]),request:parseJSON('fRequest',{}),response:parseJSON('fResponse',{}),error_response:parseJSON('fError',{})};Object.keys(body).forEach(k=>{if(body[k]===''||(Array.isArray(body[k])&&!body[k].length)||(typeof body[k]==='object'&&body[k]&&!Array.isArray(body[k])&&!Object.keys(body[k]).length))delete body[k]});const editing=!!body.id&&keys.some(k=>k.id===body.id);const d=await call('/keys',{method:editing?'PATCH':'POST',body:JSON.stringify(body)});if(d.api_key)$('createdSecret').textContent='Generated API key, copy now: '+d.api_key;toast(editing?'Saved override':'Created key');await loadAll();if((d.key||{}).id)editKey(d.key.id)}catch(e){toast(String(e.message||e),true)}}async function deleteKey(){const id=$('fId').value.trim();if(!id){toast('Select a key first',true);return}if(!confirm('Delete runtime override for '+id+'?'))return;try{await call('/keys?id='+encodeURIComponent(id),{method:'DELETE'});toast('Deleted override');newKey();await loadAll()}catch(e){toast(String(e.message||e),true)}}
async function loadUsage(){try{$('usageBox').textContent=pretty(await call('/usage'))}catch(e){$('usageBox').textContent=String(e.message||e)}}async function loadEvents(){try{const e=await call('/events');const p=await call('/policy-log');$('eventsBox').textContent=pretty({events:e.events||[],policy_log:p.policy_log||[]})}catch(e){$('eventsBox').textContent=String(e.message||e)}}async function exportState(){try{$('stateText').value=pretty((await call('/export')).state||{})}catch(e){toast(String(e.message||e),true)}}async function importState(replace){try{const state=JSON.parse($('stateText').value||'{}');await call('/import',{method:'POST',body:JSON.stringify({replace:!!replace,state})});toast('Imported');await loadAll()}catch(e){toast(String(e.message||e),true)}}function buildSafeConfig(){$('configText').value='plugins:\n  enabled: true\n  dir: "plugins"\n  configs:\n    cpa-policy-hub:\n      enabled: true\n      priority: 100\n      storage_path: "cpa-policy-hub-state.json"\n      traffic_enabled: false\n      exclusive: false\n      manage_config_api_keys: false\n      fail_closed: false\n      dry_run: true\n      default_allowed_models: ["*"]\n      auth:\n        exclusive: false\n        keys: []\n      pricing: []\n      policies: []\n      endpoint_overrides: []\n'}function buildTakeoverConfig(){$('configText').value='api-keys:\n  - "sk-client-a"\n\nplugins:\n  enabled: true\n  dir: "plugins"\n  configs:\n    cpa-policy-hub:\n      enabled: true\n      priority: 1\n      storage_path: "cpa-policy-hub-state.json"\n      traffic_enabled: true\n      config_path: "/CLIProxyAPI/config.yaml"\n      manage_config_api_keys: true\n      exclusive: true\n      fail_closed: false\n      dry_run: true\n      default_allowed_models: ["*"]\n      default_daily_token_limit: 100000\n      default_monthly_token_limit: 1000000\n      default_request_limit_per_minute: 60\n      auth:\n        exclusive: true\n        keys: []\n      pricing: []\n      policies: []\n      endpoint_overrides: []\n'}function buildPolicyConfig(){$('configText').value='policies:\n  - name: "route-alias-to-responses"\n    match:\n      providers: ["openai"]\n      models: ["public-responses-alias"]\n      request_paths: ["/chat/completions"]\n    interface:\n      force_interface: "responses"\n    request:\n      set_model: "real-upstream-responses-model"\n'}buildSafeConfig();newKey();</script></body></html>`
}

func statusHTMLPage() string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CPA Policy Hub</title><style>
:root{color-scheme:dark;--bg:#020617;--panel:#0f172a;--card:#111827;--line:#334155;--text:#e5e7eb;--muted:#94a3b8;--blue:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444}*{box-sizing:border-box}body{margin:0;font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(135deg,#020617,#111827 50%,#172554);color:var(--text)}header{padding:28px 32px 18px;border-bottom:1px solid rgba(255,255,255,.08)}h1{margin:0 0 8px;font-size:28px}h2{margin:0 0 10px}.muted{color:var(--muted)}main{padding:24px 32px 42px;display:grid;gap:18px}.bar,.grid,.split{display:grid;gap:16px}.bar{grid-template-columns:1fr auto}.grid{grid-template-columns:repeat(4,minmax(150px,1fr))}.split{grid-template-columns:minmax(520px,1.35fr) minmax(360px,.9fr)}.card{background:rgba(15,23,42,.86);border:1px solid rgba(148,163,184,.22);border-radius:18px;box-shadow:0 18px 50px rgba(0,0,0,.28);padding:18px}.stat{font-size:28px;font-weight:800;margin-top:4px}.pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:5px 10px;color:var(--muted)}.ok{color:var(--ok);border-color:rgba(34,197,94,.45)}.warn{color:var(--warn);border-color:rgba(245,158,11,.45)}.bad{color:var(--bad);border-color:rgba(239,68,68,.45)}input,select,textarea,button{font:inherit;border-radius:10px;border:1px solid var(--line);background:#020617;color:var(--text);padding:10px 12px}textarea{width:100%;min-height:150px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}button{cursor:pointer;background:#0f172a}button.primary{background:linear-gradient(135deg,#0284c7,#2563eb);border:0;font-weight:700}button.danger{border-color:rgba(239,68,68,.55);color:#fecaca}.form{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.form .full{grid-column:1/-1}label{display:grid;gap:6px;color:var(--muted)}label span{font-size:12px;text-transform:uppercase;letter-spacing:.04em}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid rgba(148,163,184,.18);padding:10px;text-align:left;vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}.actions{display:flex;gap:8px;flex-wrap:wrap}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tab{padding:9px 12px}.tab.active{background:#1d4ed8}.hidden{display:none}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.notice{border-left:4px solid var(--blue);padding:10px 12px;background:rgba(56,189,248,.09);border-radius:12px}.toast{position:fixed;right:20px;bottom:20px;max-width:520px;background:#020617;border:1px solid var(--line);border-radius:14px;padding:12px 14px;box-shadow:0 20px 60px rgba(0,0,0,.35)}@media(max-width:1000px){.grid,.split,.bar{grid-template-columns:1fr}.form{grid-template-columns:1fr}}
</style></head><body><header><h1>CPA Policy Hub</h1><div class="muted">Visual management for keys, quotas, usage and runtime state.</div></header><main>
<section class="card bar"><label><span>Management key</span><input id="mk" type="password" autocomplete="off" placeholder="Paste CPA / CPAMC management key"></label><div class="actions" style="align-self:end"><button class="primary" onclick="connect()">Connect</button><button onclick="clearKey()">Clear</button></div></section>
<section class="grid"><div class="card"><div class="muted">Traffic</div><div id="sTraffic" class="stat">-</div></div><div class="card"><div class="muted">Configured keys</div><div id="sConfigured" class="stat">-</div></div><div class="card"><div class="muted">Managed overrides</div><div id="sManaged" class="stat">-</div></div><div class="card"><div class="muted">Tracked keys</div><div id="sTracked" class="stat">-</div></div></section>
<section class="card"><div class="tabs"><button class="tab active" data-tab="keys">Keys</button><button class="tab" data-tab="usage">Usage</button><button class="tab" data-tab="events">Events</button><button class="tab" data-tab="state">Backup</button><button class="tab" data-tab="config">Config helper</button></div></section>
<section id="keys" class="view split"><div class="card"><div class="bar"><div><h2>Keys</h2><div class="muted">Edit imported CPA keys by saving a runtime override. Delete the override to fall back to config.yaml.</div></div><button onclick="loadAll()">Refresh</button></div><div style="overflow:auto"><table><thead><tr><th>Name</th><th>ID</th><th>Source</th><th>Limits</th><th>Usage</th><th></th></tr></thead><tbody id="keyRows"><tr><td colspan="6" class="muted">Connect first.</td></tr></tbody></table></div></div><div class="card"><h2 id="formTitle">Create / edit key</h2><div class="form"><label><span>ID</span><input id="fId" placeholder="auto for new key"></label><label><span>Name</span><input id="fName" placeholder="Team A"></label><label class="full"><span>Plain API key</span><input id="fKey" placeholder="Only needed when creating or replacing key material"></label><label><span>Daily tokens</span><input id="fDaily" type="number" min="0" placeholder="0 = unlimited"></label><label><span>Monthly tokens</span><input id="fMonthly" type="number" min="0" placeholder="0 = unlimited"></label><label><span>Total tokens</span><input id="fTotal" type="number" min="0" placeholder="0 = unlimited"></label><label><span>RPM</span><input id="fRpm" type="number" min="0" placeholder="requests/minute"></label><label class="full"><span>Allowed models</span><input id="fModels" placeholder="*, gpt-4o*, claude*"></label><label><span>Tenant</span><input id="fTenant"></label><label><span>Plan</span><input id="fPlan"></label><label><span>Disabled</span><select id="fDisabled"><option value="false">No</option><option value="true">Yes</option></select></label><label><span>Expires at</span><input id="fExpires" placeholder="2026-12-31T00:00:00Z"></label></div><div class="actions" style="margin-top:14px"><button class="primary" onclick="saveKey()">Save</button><button onclick="newKey()">New</button><button class="danger" onclick="deleteKey()">Delete override</button></div><div class="notice" style="margin-top:14px">For imported CPA <span class="mono">api-keys</span>, Save writes an override to <span class="mono">cpa-policy-hub-state.json</span>. It does not edit CPA <span class="mono">config.yaml</span>.</div><pre id="createdSecret" class="mono muted"></pre></div></section>
<section id="usage" class="view card hidden"><div class="bar"><h2>Usage</h2><button onclick="loadUsage()">Refresh</button></div><div id="usageBox" class="mono muted">Connect first.</div></section>
<section id="events" class="view card hidden"><div class="bar"><h2>Recent events</h2><button onclick="loadEvents()">Refresh</button></div><div id="eventsBox" class="mono muted">Connect first.</div></section>
<section id="state" class="view card hidden"><h2>Backup / restore</h2><div class="actions"><button onclick="exportState()">Export state</button><button onclick="importState(false)">Import merge</button><button class="danger" onclick="importState(true)">Import replace</button></div><textarea id="stateText" placeholder="Exported state appears here"></textarea></section>
<section id="config" class="view card hidden"><h2>Config helper</h2><p class="muted">Safe starter config. Enable traffic only after the plugin page works.</p><div class="actions"><button onclick="buildSafeConfig()">Generate safe config</button><button onclick="buildTakeoverConfig()">Generate takeover config</button></div><textarea id="configText"></textarea></section>
</main><div id="toast" class="toast hidden"></div><script>
const api='/v0/management/plugins/cpa-policy-hub';let managementKey='';let keys=[];const $=id=>document.getElementById(id);function toast(m,bad){const t=$('toast');t.textContent=m;t.className='toast '+(bad?'bad':'ok');setTimeout(()=>t.className='toast hidden',4200)}function pretty(v){return JSON.stringify(v,null,2)}function esc(s){return String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}function csv(s){return String(s||'').split(',').map(x=>x.trim()).filter(Boolean)}function num(id){const v=$(id).value;return v===''?0:Number(v)}async function call(path,opt){if(!managementKey)throw new Error('management key required');opt=opt||{};opt.headers=Object.assign({'Authorization':'Bearer '+managementKey},opt.headers||{});if(opt.body&&!opt.headers['Content-Type'])opt.headers['Content-Type']='application/json';const r=await fetch(api+path,opt);const text=await r.text();let d;try{d=JSON.parse(text)}catch(e){throw new Error(text||r.status)}if(!r.ok)throw new Error(d.error||text||r.status);return d}
function connect(){managementKey=$('mk').value.trim();if(!managementKey){toast('Paste management key first',true);return}loadAll()}function clearKey(){managementKey='';$('mk').value='';keys=[];renderKeys();toast('Cleared')}document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('hidden',v.id!==b.dataset.tab));});
async function loadAll(){try{await loadStatus();await loadKeys();await loadUsage();await loadEvents()}catch(e){toast(String(e.message||e),true)}}async function loadStatus(){const s=await call('/status');$('sTraffic').textContent=s.traffic_enabled?'Enabled':'Off';$('sTraffic').className='stat '+(s.traffic_enabled?'ok':'warn');$('sConfigured').textContent=s.configured_keys||0;$('sManaged').textContent=s.managed_keys||0;$('sTracked').textContent=s.tracked_keys||0;if(s.config_load_error)toast('Config load error: '+s.config_load_error,true)}async function loadKeys(){const d=await call('/keys');keys=d.keys||[];renderKeys()}function renderKeys(){const tb=$('keyRows');if(!keys.length){tb.innerHTML='<tr><td colspan="6" class="muted">No keys loaded.</td></tr>';return}tb.innerHTML=keys.map(k=>{const u=k.usage||{};const limits='daily '+(k.daily_token_limit||0)+' / monthly '+(k.monthly_token_limit||0)+' / rpm '+(k.request_limit_per_minute||0);const usage='tokens '+(u.total_tokens||0)+' / requests '+(u.total_requests||0);return '<tr><td>'+esc(k.name||'-')+'</td><td class="mono">'+esc(k.id)+'</td><td><span class="pill '+(k.source==='config'?'warn':'ok')+'">'+esc(k.source||'managed')+'</span></td><td>'+esc(limits)+'</td><td>'+esc(usage)+'</td><td><button onclick="editKey(\''+esc(k.id)+'\')">Edit</button></td></tr>'}).join('')}function editKey(id){const k=keys.find(x=>x.id===id);if(!k)return;$('formTitle').textContent='Edit '+(k.name||id);$('fId').value=k.id||'';$('fName').value=k.name||'';$('fKey').value='';$('fDaily').value=k.daily_token_limit||0;$('fMonthly').value=k.monthly_token_limit||0;$('fTotal').value=k.total_token_limit||0;$('fRpm').value=k.request_limit_per_minute||0;$('fModels').value=(k.allowed_models||[]).join(', ');$('fTenant').value=k.tenant||'';$('fPlan').value=k.plan||'';$('fDisabled').value=k.disabled?'true':'false';$('fExpires').value=k.expires_at||'';$('createdSecret').textContent=''}function newKey(){$('formTitle').textContent='Create managed key';['fId','fName','fKey','fDaily','fMonthly','fTotal','fRpm','fModels','fTenant','fPlan','fExpires'].forEach(id=>$(id).value='');$('fDisabled').value='false';$('createdSecret').textContent=''}async function saveKey(){try{const body={id:$('fId').value.trim(),name:$('fName').value.trim(),key:$('fKey').value.trim(),daily_token_limit:num('fDaily'),monthly_token_limit:num('fMonthly'),total_token_limit:num('fTotal'),request_limit_per_minute:num('fRpm'),allowed_models:csv($('fModels').value),tenant:$('fTenant').value.trim(),plan:$('fPlan').value.trim(),disabled:$('fDisabled').value==='true',expires_at:$('fExpires').value.trim()};Object.keys(body).forEach(k=>{if(body[k]===''||(Array.isArray(body[k])&&!body[k].length))delete body[k]});const editing=!!body.id&&keys.some(k=>k.id===body.id);const d=await call('/keys',{method:editing?'PATCH':'POST',body:JSON.stringify(body)});if(d.api_key)$('createdSecret').textContent='Generated API key, copy now: '+d.api_key;toast(editing?'Saved override':'Created key');await loadAll();if((d.key||{}).id)editKey(d.key.id)}catch(e){toast(String(e.message||e),true)}}async function deleteKey(){const id=$('fId').value.trim();if(!id){toast('Select a key first',true);return}if(!confirm('Delete runtime override for '+id+'?'))return;try{await call('/keys?id='+encodeURIComponent(id),{method:'DELETE'});toast('Deleted override');newKey();await loadAll()}catch(e){toast(String(e.message||e),true)}}
async function loadUsage(){try{const d=await call('/usage');$('usageBox').innerHTML='<pre class="mono">'+esc(pretty(d))+'</pre>'}catch(e){$('usageBox').textContent=String(e.message||e)}}async function loadEvents(){try{const e=await call('/events');const p=await call('/policy-log');$('eventsBox').innerHTML='<h3>Usage events</h3><pre class="mono">'+esc(pretty(e.events||[]))+'</pre><h3>Policy log</h3><pre class="mono">'+esc(pretty(p.events||[]))+'</pre>'}catch(e){$('eventsBox').textContent=String(e.message||e)}}async function exportState(){try{const d=await call('/export');$('stateText').value=pretty(d.state||{})}catch(e){toast(String(e.message||e),true)}}async function importState(replace){try{const state=JSON.parse($('stateText').value||'{}');await call('/import',{method:'POST',body:JSON.stringify({replace:!!replace,state})});toast('Imported');await loadAll()}catch(e){toast(String(e.message||e),true)}}function buildSafeConfig(){$('configText').value='plugins:\n  enabled: true\n  dir: "plugins"\n  configs:\n    cpa-policy-hub:\n      enabled: true\n      priority: 100\n      storage_path: "cpa-policy-hub-state.json"\n      traffic_enabled: false\n      exclusive: false\n      manage_config_api_keys: false\n      fail_closed: false\n      dry_run: true\n      default_allowed_models: ["*"]\n      default_daily_token_limit: 0\n      default_monthly_token_limit: 0\n      default_request_limit_per_minute: 0\n      policies: []\n      endpoint_overrides: []\n'}function buildTakeoverConfig(){$('configText').value='plugins:\n  enabled: true\n  dir: "plugins"\n  configs:\n    cpa-policy-hub:\n      enabled: true\n      priority: 1\n      storage_path: "cpa-policy-hub-state.json"\n      traffic_enabled: true\n      config_path: "/CLIProxyAPI/config.yaml"\n      manage_config_api_keys: true\n      exclusive: true\n      fail_closed: false\n      dry_run: false\n      default_allowed_models: ["*"]\n      default_daily_token_limit: 100000\n      default_monthly_token_limit: 1000000\n      default_request_limit_per_minute: 60\n      policies: []\n      endpoint_overrides: []\n'}buildSafeConfig();newKey();
</script></body></html>`
}

func statusHTML() string {
	return statusHTMLPage()
}

func legacyStatusHTML() string {
	const page = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
	<title>CPA Policy Hub</title>
  <style>
		:root{color-scheme:dark;--bg:#0f172a;--panel:#111827;--panel2:#1e293b;--line:#334155;--text:#e2e8f0;--muted:#94a3b8;--blue:#60a5fa;--green:#34d399;--red:#fb7185;--yellow:#fbbf24}*{box-sizing:border-box}body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;background:linear-gradient(135deg,#0f172a,#111827);color:var(--text)}main{max-width:1220px;margin:0 auto;padding:32px 20px 56px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}.title h1{margin:0;font-size:30px}.title p{margin:8px 0 0;color:var(--muted)}.pill{border:1px solid var(--line);background:#02061766;border-radius:999px;padding:8px 12px;color:var(--muted)}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.tab{border:1px solid var(--line);background:#02061766;color:var(--text);border-radius:12px;padding:10px 14px;cursor:pointer}.tab.active{border-color:var(--blue);background:#1d4ed833}.card{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 20px 50px #0005;margin-bottom:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}.metric{background:var(--panel2);border-radius:14px;padding:14px;border:1px solid #ffffff0a}.metric span{color:var(--muted);font-size:12px}.metric b{display:block;font-size:26px;margin-top:8px}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.hidden{display:none}.btn{border:1px solid var(--line);background:#2563eb;color:white;border-radius:10px;padding:9px 12px;cursor:pointer}.btn.secondary{background:#334155}.btn.danger{background:#be123c}.btn:disabled{opacity:.5;cursor:not-allowed}input,textarea,select{width:100%;background:#020617;border:1px solid var(--line);border-radius:10px;color:var(--text);padding:10px}label{display:block;color:var(--muted);font-size:12px;margin:10px 0 6px}textarea{min-height:120px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}pre{background:#020617;border:1px solid var(--line);border-radius:12px;padding:14px;overflow:auto;max-height:420px}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #33415588;text-align:left;padding:10px;vertical-align:top}th{color:var(--muted);font-size:12px}.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--yellow)}code{color:#93c5fd}.split{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}.small{font-size:12px;color:var(--muted)}
	</style>
</head>
<body><main>
	<div class="top"><div class="title"><h1>CPA Policy Hub</h1><p>Embedded management UI for keys, usage, policies, counters, and config snippets.</p></div><div style="min-width:320px"><label>Management key</label><input id="managementKey" type="password" placeholder="remote-management.secret-key / MANAGEMENT_PASSWORD"><div class="row" style="margin-top:8px"><button class="btn secondary" onclick="saveManagementKey()">Use key</button><div class="pill" id="health">Loading...</div></div></div></div>
	<div class="tabs">
		<button class="tab active" data-tab="dashboard">Dashboard</button><button class="tab" data-tab="keys">Keys</button><button class="tab" data-tab="usage">Usage</button><button class="tab" data-tab="logs">Logs</button><button class="tab" data-tab="tools">Tools</button><button class="tab" data-tab="builder">Config Builder</button>
	</div>
	<section id="dashboard" class="view"><div class="card"><div class="row"><button class="btn" onclick="loadAll()">Refresh</button><span class="small">Data is loaded through Management API; sign in to CPAMC if requests fail.</span></div></div><div class="grid" id="metrics"></div><div class="card"><h3>Status JSON</h3><pre id="statusRaw">{}</pre></div></section>
	<section id="keys" class="view hidden"><div class="split"><div class="card"><h3>Create managed key</h3><label>ID</label><input id="keyId" placeholder="team-a-dev"><label>Name</label><input id="keyName" placeholder="Team A Dev"><label>Plain API key (optional; generated if empty)</label><input id="keyPlain" placeholder="shown only once"><label>Tenant</label><input id="keyTenant" placeholder="team-a"><label>Plan</label><input id="keyPlan" placeholder="basic"><label>Allowed models, comma separated</label><input id="keyModels" value="*"><div class="row" style="margin-top:12px"><button class="btn" onclick="createKey()">Create key</button></div><pre id="createKeyResult"></pre></div><div class="card"><h3>Managed/configured keys</h3><button class="btn secondary" onclick="loadKeys()">Refresh keys</button><div id="keysTable"></div></div></div></section>
	<section id="usage" class="view hidden"><div class="card"><div class="row"><button class="btn" onclick="loadUsage()">Refresh usage</button><button class="btn secondary" onclick="resetTarget('active')">Reset active</button></div></div><div class="split"><div class="card"><h3>Key usage</h3><pre id="usageRaw">{}</pre></div><div class="card"><h3>Policy usage / active</h3><pre id="policyUsageRaw">{}</pre></div></div></section>
	<section id="logs" class="view hidden"><div class="card"><div class="row"><button class="btn" onclick="loadLogs()">Refresh logs</button><button class="btn secondary" onclick="resetTarget('events')">Clear usage events</button><button class="btn secondary" onclick="resetTarget('policy_log')">Clear policy log</button></div></div><div class="split"><div class="card"><h3>Usage events</h3><pre id="eventsRaw">[]</pre></div><div class="card"><h3>Policy log</h3><pre id="policyLogRaw">[]</pre></div></div></section>
	<section id="tools" class="view hidden"><div class="split"><div class="card"><h3>Reset counters</h3><label>Target</label><select id="resetTarget"><option>active</option><option>usage</option><option>policy_usage</option><option>events</option><option>policy_log</option><option>all_counters</option></select><label>ID (optional)</label><input id="resetId" placeholder="counter id"><button class="btn danger" onclick="resetFromForm()" style="margin-top:12px">Reset</button><pre id="resetResult"></pre></div><div class="card"><h3>Export / Import state</h3><div class="row"><button class="btn" onclick="exportState()">Export</button><button class="btn secondary" onclick="importState(false)">Import merge</button><button class="btn danger" onclick="importState(true)">Import replace</button></div><label>State JSON</label><textarea id="stateBox" style="min-height:260px"></textarea><p class="small">Import strips plaintext keys and accepts only valid key_hash values.</p></div></div></section>
	<section id="builder" class="view hidden"><div class="card"><h3>YAML Config Builder</h3><div class="split"><div><label>Key ID</label><input id="bKey" value="team-a-main"><label>Tenant</label><input id="bTenant" value="team-a"><label>Key hash</label><input id="bHash" placeholder="sha256:..."><label>Model pattern</label><input id="bModel" value="gpt-*"><label>Daily token limit</label><input id="bDaily" value="100000"><label>Monthly cost limit</label><input id="bCost" value="100"><button class="btn" onclick="buildYaml()" style="margin-top:12px">Generate YAML</button></div><div><label>Generated YAML</label><textarea id="yamlOut" style="min-height:360px"></textarea><p class="small">Static plugin config is still applied from CPA config.yaml; copy this into plugins.configs.cpa-policy-hub and restart CPA.</p></div></div></div></section>
</main>
<script>
const api='/v0/management/plugins/cpa-policy-hub';
let managementKey='';sessionStorage.removeItem('cpaPolicyHubManagementKey');
const $=id=>document.getElementById(id);
function saveManagementKey(){managementKey=$('managementKey').value.trim();sessionStorage.removeItem('cpaPolicyHubManagementKey');loadAll();}
function show(tab){document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('hidden',v.id!==tab));}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>show(b.dataset.tab));
function pretty(v){return JSON.stringify(v,null,2)}
async function call(path,opt){const o=Object.assign({},opt||{});const headers=Object.assign({'Content-Type':'application/json'},o.headers||{});if(managementKey)headers.Authorization='Bearer '+managementKey;o.headers=headers;const r=await fetch(api+path,o);const t=await r.text();let v;try{v=JSON.parse(t)}catch(e){v={error:t}}if(!r.ok)throw new Error(v.message||v.error||r.statusText);return v}
async function loadStatus(){try{const s=await call('/status');$('health').textContent='Connected v'+(s.version||'');$('health').className='pill ok';$('statusRaw').textContent=pretty(s);$('metrics').innerHTML=['policies','configured_keys','managed_keys','tracked_keys','policy_events','policy_counters','active_counters'].map(k=>'<div class="metric"><span>'+k+'</span><b>'+esc(s[k]??0)+'</b></div>').join('');}catch(e){$('health').textContent='Management API unavailable';$('health').className='pill err';$('statusRaw').textContent=String(e);}}
async function loadKeys(){try{const d=await call('/keys');const rows=(d.keys||[]).map(k=>'<tr><td>'+esc(k.id)+'</td><td>'+esc(k.name||'')+'</td><td>'+esc(k.tenant||'')+'</td><td>'+esc(k.plan||'')+'</td><td>'+esc((k.allowed_models||[]).join(','))+'</td><td><button class="btn danger" data-delete-key="'+escAttr(k.id)+'">Delete</button></td></tr>').join('');$('keysTable').innerHTML='<table><thead><tr><th>ID</th><th>Name</th><th>Tenant</th><th>Plan</th><th>Models</th><th></th></tr></thead><tbody>'+rows+'</tbody></table>';$('keysTable').querySelectorAll('[data-delete-key]').forEach(b=>b.onclick=()=>deleteKey(b.dataset.deleteKey));}catch(e){$('keysTable').innerHTML='<p class="err">'+esc(String(e))+'</p>';}}
async function createKey(){const models=$('keyModels').value.split(',').map(x=>x.trim()).filter(Boolean);const body={id:$('keyId').value.trim(),name:$('keyName').value.trim(),key:$('keyPlain').value.trim(),tenant:$('keyTenant').value.trim(),plan:$('keyPlan').value.trim(),allowed_models:models};try{const d=await call('/keys',{method:'POST',body:JSON.stringify(body)});$('createKeyResult').textContent=pretty(d);loadKeys();}catch(e){$('createKeyResult').textContent=String(e);}}
async function deleteKey(id){if(!confirm('Delete managed key '+id+'?'))return;await call('/keys?id='+encodeURIComponent(id),{method:'DELETE'});loadKeys();}
async function loadUsage(){try{const d=await call('/usage');$('usageRaw').textContent=pretty(d.usage||{});$('policyUsageRaw').textContent=pretty({policy_usage:d.policy_usage||{},active:d.active||{}});}catch(e){$('usageRaw').textContent=String(e);}}
async function loadLogs(){try{const e=await call('/events?limit=100');$('eventsRaw').textContent=pretty(e.events||[]);const p=await call('/policy-log?limit=100');$('policyLogRaw').textContent=pretty(p.policy_log||[]);}catch(err){$('policyLogRaw').textContent=String(err);}}
async function resetTarget(t){if(!confirm('Reset '+t+'?'))return;const d=await call('/reset',{method:'POST',body:JSON.stringify({target:t})});alert(pretty(d));loadAll();}
async function resetFromForm(){const body={target:$('resetTarget').value,id:$('resetId').value.trim()};try{$('resetResult').textContent=pretty(await call('/reset',{method:'POST',body:JSON.stringify(body)}));loadAll();}catch(e){$('resetResult').textContent=String(e);}}
async function exportState(){const d=await call('/export');$('stateBox').value=pretty(d.state||{});}
async function importState(replace){if(!confirm((replace?'Replace':'Merge')+' state?'))return;let state=JSON.parse($('stateBox').value||'{}');const d=await call('/import',{method:'POST',body:JSON.stringify({replace,state})});alert(pretty(d));loadAll();}
function buildYaml(){const y='plugins:\n  enabled: true\n  dir: "plugins"\n  configs:\n    cpa-policy-hub:\n      enabled: true\n      priority: 100\n      storage_path: "cpa-policy-hub-state.json"\n      traffic_enabled: false\n      exclusive: false\n      manage_config_api_keys: false\n      fail_closed: false\n      dry_run: true\n      expose_limit_headers: false\n      default_allowed_models: ["*"]\n      default_daily_token_limit: 0\n      default_monthly_token_limit: 0\n      default_request_limit_per_minute: 0\n      auth:\n        exclusive: false\n        keys: []\n      pricing: []\n      policies: []\n      endpoint_overrides: []\n';$('yamlOut').value=y;}
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function escAttr(s){return esc(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
async function loadAll(){if(!managementKey){$('health').textContent='Enter management key';$('health').className='pill';$('statusRaw').textContent='Paste the CPA management key first. No Management API requests are sent until a key is provided.';return;}await loadStatus();if(!$('health').className.includes('ok'))return;await loadKeys();await loadUsage();await loadLogs();}
if(managementKey)$('managementKey').value=managementKey;
loadAll();buildYaml();
</script></body></html>`
	return page
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
