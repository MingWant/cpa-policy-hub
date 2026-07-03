package main

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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
	PreserveClientCredentials    bool                   `yaml:"preserve_client_credentials" json:"preserve_client_credentials"`
	FailClosed                   bool                   `yaml:"fail_closed" json:"fail_closed"`
	DryRun                       bool                   `yaml:"dry_run" json:"dry_run"`
	ExposeLimitHeaders           bool                   `yaml:"expose_limit_headers" json:"expose_limit_headers"`
	DebugLog                     bool                   `yaml:"debug_log" json:"debug_log"`
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
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"api-key":             {},
	"x-goog-api-key":      {},
	"x-cli-key":           {},
	"host":                {},
}

var protectedResponseHeaders = map[string]struct{}{
	"set-cookie": {},
	"server":     {},
}

type timeWindowRule struct {
	Name     string   `yaml:"name" json:"name,omitempty"`
	Timezone string   `yaml:"timezone" json:"timezone,omitempty"`
	Days     []string `yaml:"days" json:"days,omitempty"`
	Start    string   `yaml:"start" json:"start,omitempty"`
	End      string   `yaml:"end" json:"end,omitempty"`
	Deny     bool     `yaml:"deny" json:"deny,omitempty"`
	Message  string   `yaml:"message" json:"message,omitempty"`
}

type errorResponseRule struct {
	Name             string            `yaml:"name" json:"name,omitempty"`
	StatusCode       int               `yaml:"status_code" json:"status_code,omitempty"`
	Message          string            `yaml:"message" json:"message,omitempty"`
	Body             string            `yaml:"body" json:"body,omitempty"`
	JSON             map[string]any    `yaml:"json" json:"json,omitempty"`
	SetHeaders       map[string]string `yaml:"set_headers" json:"set_headers,omitempty"`
	HideUpstream     bool              `yaml:"hide_upstream" json:"hide_upstream,omitempty"`
	UpstreamStatuses []int             `yaml:"upstream_statuses" json:"upstream_statuses,omitempty"`
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
	KeyFingerprint        string                 `yaml:"-" json:"key_fingerprint,omitempty"`
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
	Action       string    `json:"action,omitempty"`
	Source       string    `json:"source,omitempty"`
	Provider     string    `json:"provider,omitempty"`
	Model        string    `json:"model,omitempty"`
	RequestPath  string    `json:"request_path,omitempty"`
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
	mu                sync.RWMutex
	cfg               pluginConfig
	configuredKeys    map[string]keyRule
	credentialIndex   map[string]string
	state             persistedState
	configLoadError   string
	dirty             bool
	saveSignal        chan struct{}
	stopSignal        chan struct{}
	stopOnce          sync.Once
	snapshot          atomic.Pointer[runtimeSnapshot]
}

type runtimeSnapshot struct {
	cfg             pluginConfig
	keyRules        map[string]keyRule
	credentialIndex map[string]string
	configLoadError string
	capabilities    capabilities
	configuredCount int
	managedCount    int
}

type requestDebugInfo struct {
	MetadataTopKeys           []string `json:"metadata_top_keys,omitempty"`
	AccessMetadataKeys        []string `json:"access_metadata_keys,omitempty"`
	ResolvedKeyID             string   `json:"resolved_key_id,omitempty"`
	ClientCredentialPresent   bool     `json:"client_credential_present"`
	ClientCredentialSource    string   `json:"client_credential_source,omitempty"`
	PassthroughHeaders        []string `json:"passthrough_headers,omitempty"`
	DryRun                    bool     `json:"dry_run"`
	ToFormat                  string   `json:"to_format,omitempty"`
	RequestedModel            string   `json:"requested_model,omitempty"`
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
