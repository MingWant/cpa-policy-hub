package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

func configure(raw []byte) error {
	if errFlush := currentLimiter.flushStateNow(); errFlush != nil {
		currentLimiter.mu.RLock()
		failClosed := currentLimiter.cfg.FailClosed
		currentLimiter.mu.RUnlock()
		if failClosed {
			return errFlush
		}
	}
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
	currentLimiter.dirty = false
	currentLimiter.refreshRuntimeSnapshotLocked()
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
		rules = append(rules, keyRule{ID: id, Name: "CPA config api-key " + maskAPIKey(key), KeyFingerprint: maskAPIKey(key), KeyHash: hash})
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
	runtimeCapabilities := currentLimiter.runtimeCapabilities()
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
				{Name: "preserve_client_credentials", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Forward the original frontend API key back to CPA after plugin authentication for passthrough-style deployments."},
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

func computeRuntimeCapabilities(cfg pluginConfig, configuredKeys map[string]keyRule, managedKeys map[string]keyRule) capabilities {
	if !cfg.TrafficEnabled {
		return capabilities{ManagementAPI: true}
	}
	hasAuthKeys := len(configuredKeys) > 0 || len(managedKeys) > 0
	hasRequestPolicies := (cfg.PreserveClientCredentials && hasAuthKeys) || len(cfg.Policies) > 0 || len(cfg.EndpointOverrides) > 0 || anyKeyRequestPolicyLocked(configuredKeys) || anyKeyRequestPolicyLocked(managedKeys)
	hasResponsePolicies := len(cfg.Policies) > 0 || cfg.ExposeLimitHeaders || anyKeyResponsePolicyLocked(configuredKeys) || anyKeyResponsePolicyLocked(managedKeys)
	hasUsage := hasAuthKeys || len(cfg.Policies) > 0 || len(cfg.Pricing) > 0
	return capabilities{
		FrontendAuthProvider:          hasAuthKeys,
		FrontendAuthProviderExclusive: hasAuthKeys && cfg.Exclusive,
		RequestInterceptor:            hasRequestPolicies,
		ResponseInterceptor:           hasResponsePolicies,
		UsagePlugin:                   hasUsage,
		ManagementAPI:                 true,
	}
}

func (l *limiter) runtimeCapabilitiesLocked() capabilities {
	if snapshot := l.snapshot.Load(); snapshot != nil {
		return snapshot.capabilities
	}
	return computeRuntimeCapabilities(l.cfg, l.configuredKeys, l.state.Keys)
}

func (l *limiter) runtimeCapabilities() capabilities {
	if l == nil {
		return capabilities{ManagementAPI: true}
	}
	if snapshot := l.currentSnapshot(); snapshot != nil {
		return snapshot.capabilities
	}
	return capabilities{ManagementAPI: true}
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
	if snapshot := l.currentSnapshot(); snapshot != nil {
		return snapshot.cfg.TrafficEnabled
	}
	return false
}
