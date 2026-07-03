package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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
	snapshot := currentLimiter.currentSnapshot()
	currentLimiter.mu.RLock()
	defer currentLimiter.mu.RUnlock()
	trafficEnabled := currentLimiter.trafficEnabledLocked()
	configLoadError := currentLimiter.configLoadError
	configuredKeys := len(currentLimiter.configuredKeys)
	managedKeys := len(currentLimiter.state.Keys)
	capabilities := currentLimiter.runtimeCapabilitiesLocked()
	if snapshot != nil {
		configLoadError = snapshot.configLoadError
		configuredKeys = snapshot.configuredCount
		managedKeys = snapshot.managedCount
		capabilities = snapshot.capabilities
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{
		"plugin":                      pluginID,
		"name":                        pluginDisplayName,
		"legacy_plugin":               legacyPluginID,
		"version":                     pluginVersion,
		"capabilities":                capabilities,
		"traffic_enabled":             trafficEnabled,
		"traffic_config_enabled":      currentLimiter.cfg.TrafficEnabled,
		"exclusive":                   currentLimiter.cfg.Exclusive,
		"storage_path":                currentLimiter.cfg.StoragePath,
		"config_path":                 currentLimiter.cfg.ConfigPath,
		"manage_config_api_keys":      currentLimiter.cfg.ManageConfigAPIKeys,
		"preserve_client_credentials": currentLimiter.cfg.PreserveClientCredentials,
		"config_load_error":           configLoadError,
		"policies":                    len(currentLimiter.cfg.Policies),
		"endpoint_rules":              len(currentLimiter.cfg.EndpointOverrides),
		"configured_keys":             configuredKeys,
		"managed_keys":                managedKeys,
		"tracked_keys":                len(currentLimiter.state.Usage),
		"policy_events":               len(currentLimiter.state.PolicyLog),
		"policy_counters":             len(currentLimiter.state.Policies),
		"active_counters":             len(currentLimiter.state.Active),
		"updated_at":                  currentLimiter.state.UpdatedAt,
	}))
}

func managementListKeys() ([]byte, error) {
	currentLimiter.mu.RLock()
	defer currentLimiter.mu.RUnlock()
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
	currentLimiter.rebuildCredentialIndexLocked()
	currentLimiter.markDirtyLocked()
	currentLimiter.mu.Unlock()
	if errSave := currentLimiter.flushStateNow(); errSave != nil {
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
	currentLimiter.rebuildCredentialIndexLocked()
	currentLimiter.markDirtyLocked()
	currentLimiter.mu.Unlock()
	if errSave := currentLimiter.flushStateNow(); errSave != nil {
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
	if patch.KeyFingerprint == "" {
		patch.KeyFingerprint = existing.KeyFingerprint
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
	currentLimiter.rebuildCredentialIndexLocked()
	currentLimiter.markDirtyLocked()
	currentLimiter.mu.Unlock()
	if errSave := currentLimiter.flushStateNow(); errSave != nil {
		return nil, errSave
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"deleted": id}))
}

func managementUsage(req managementRequest) ([]byte, error) {
	id := strings.TrimSpace(req.Query.Get("id"))
	currentLimiter.mu.RLock()
	defer currentLimiter.mu.RUnlock()
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
	currentLimiter.mu.RLock()
	defer currentLimiter.mu.RUnlock()
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
	currentLimiter.mu.RLock()
	defer currentLimiter.mu.RUnlock()
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
			currentLimiter.mu.Unlock()
			return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "resetting all managed keys requires target managed_keys_all"}))
		}
	case "managed_keys_all":
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "bulk managed key deletion is not supported by reset; delete keys individually"}))
	default:
		currentLimiter.mu.Unlock()
		return okEnvelope(jsonResponse(http.StatusBadRequest, map[string]any{"error": "unsupported target"}))
	}
	if reset.Target == "keys" || reset.Target == "managed_keys" || reset.Target == "managed_keys_all" {
		currentLimiter.rebuildCredentialIndexLocked()
	}
	currentLimiter.markDirtyLocked()
	currentLimiter.mu.Unlock()
	if errSave := currentLimiter.flushStateNow(); errSave != nil {
		return nil, errSave
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"reset": reset.Target, "id": reset.ID}))
}

func managementExport() ([]byte, error) {
	currentLimiter.mu.RLock()
	defer currentLimiter.mu.RUnlock()
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
	currentLimiter.rebuildCredentialIndexLocked()
	currentLimiter.markDirtyLocked()
	currentLimiter.mu.Unlock()
	if errSave := currentLimiter.flushStateNow(); errSave != nil {
		return nil, errSave
	}
	return okEnvelope(jsonResponse(http.StatusOK, map[string]any{"imported": true, "replace": request.Replace}))
}
