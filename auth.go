package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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
	rule, ok := currentLimiter.keyRuleByCredential(credential)
	currentLimiter.logAuthDebug(authDebugInfo{
		Source:             source,
		RequestPath:        normalizeEndpointPath(req.Path),
		Provider:           provider,
		Model:              model,
		CredentialPresent:  credential != "",
		CredentialMasked:   maskAPIKey(credential),
		CredentialHash:     maskHash(hashAPIKey(credential)),
		MatchedKeyID:       rule.ID,
		MatchedKeyHash:     maskHash(rule.KeyHash),
		LoadedKeyCount:     currentLimiter.snapshotKeyCount(),
		LoadedKeyHashes:    currentLimiter.snapshotKeyHashes(),
		ManageConfigAPIKey: currentLimiter.manageConfigAPIKeysEnabled(),
	})
	if !ok || !rule.usable(now) || !keyPolicyAllowed(rule, model, provider, now) {
		currentLimiter.mu.Lock()
		currentLimiter.appendEventLocked(usageEvent{At: time.Now().UTC(), Action: "auth_reject", Source: source, Provider: provider, Model: model, RequestPath: normalizeEndpointPath(req.Path), Failed: true})
		currentLimiter.markDirtyLocked()
		currentLimiter.mu.Unlock()
		currentLimiter.requestStateSave()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	currentLimiter.mu.Lock()
	rule, ok = currentLimiter.keyRuleByIDLocked(rule.ID)
	if !ok || !rule.usable(now) || !keyPolicyAllowed(rule, model, provider, now) {
		currentLimiter.appendEventLocked(usageEvent{At: time.Now().UTC(), Action: "auth_reject", Source: source, Provider: provider, Model: model, RequestPath: normalizeEndpointPath(req.Path), Failed: true})
		currentLimiter.markDirtyLocked()
		currentLimiter.mu.Unlock()
		currentLimiter.requestStateSave()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	usage := currentLimiter.ensureUsageLocked(rule.ID)
	if !withinQuota(rule, usage, now) || !currentLimiter.allowRequestLocked(rule, usage, now) {
		currentLimiter.appendEventLocked(usageEvent{At: time.Now().UTC(), KeyID: rule.ID, Action: "quota_reject", Source: source, Provider: provider, Model: model, RequestPath: normalizeEndpointPath(req.Path), Failed: true})
		currentLimiter.markDirtyLocked()
		currentLimiter.mu.Unlock()
		currentLimiter.requestStateSave()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	ctx := endpointOverrideContext{KeyID: rule.ID, Provider: provider, Model: model, RequestedModel: model, RequestPath: normalizeEndpointPath(req.Path)}
	denied, deniedPolicy, deniedMessage, dryRun := currentLimiter.authDenyDecisionLocked(ctx)
	if denied && !dryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: deniedPolicy, Action: "deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, Message: deniedMessage})
		currentLimiter.markDirtyLocked()
		currentLimiter.mu.Unlock()
		currentLimiter.requestStateSave()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	if denied && dryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: deniedPolicy, Action: "would_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, DryRun: true, Message: deniedMessage})
		currentLimiter.markDirtyLocked()
	}
	quotaDenied, quotaPolicy, quotaMessage, quotaDryRun := currentLimiter.policyQuotaDecisionLocked(ctx, rule, now)
	if quotaDenied && !quotaDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: quotaPolicy, Action: "quota_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, Message: quotaMessage})
		currentLimiter.markDirtyLocked()
		currentLimiter.mu.Unlock()
		currentLimiter.requestStateSave()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	if quotaDenied && quotaDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: quotaPolicy, Action: "would_quota_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, DryRun: true, Message: quotaMessage})
		currentLimiter.markDirtyLocked()
	}
	concurrencyDenied, concurrencyPolicy, concurrencyMessage, concurrencyDryRun := currentLimiter.policyConcurrencyDecisionLocked(ctx, rule)
	if concurrencyDenied && !concurrencyDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: concurrencyPolicy, Action: "concurrency_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, Message: concurrencyMessage})
		currentLimiter.markDirtyLocked()
		currentLimiter.mu.Unlock()
		currentLimiter.requestStateSave()
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	if concurrencyDenied && concurrencyDryRun {
		currentLimiter.appendPolicyEventLocked(policyEvent{At: time.Now().UTC(), Policy: concurrencyPolicy, Action: "would_concurrency_deny", KeyID: rule.ID, Model: model, RequestPath: ctx.RequestPath, DryRun: true, Message: concurrencyMessage})
		currentLimiter.markDirtyLocked()
	}
	currentLimiter.markDirtyLocked()
	failClosed := currentLimiter.cfg.FailClosed
	preserveClientCredentials := currentLimiter.cfg.PreserveClientCredentials
	currentLimiter.mu.Unlock()
	var errSave error
	if failClosed {
		errSave = currentLimiter.flushStateNow()
	} else {
		currentLimiter.requestStateSave()
	}
	if errSave != nil && failClosed {
		return okEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false})
	}
	metadata := map[string]string{
		"provider":        pluginID,
		"legacy_provider": legacyPluginID,
		"source":          source,
		"key_id":          rule.ID,
	}
	copyCredentialHeaders(req.Headers, metadata)
	if preserveClientCredentials {
		metadata["client_credential"] = credential
		metadata["client_credential_source"] = source
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
	case "provider", "legacy_provider", "source", "key_id", "tenant", "plan", "client_credential", "client_credential_source", "header_authorization", "header_api_key", "header_x_api_key", "header_x_goog_api_key":
		return true
	default:
		return false
	}
}

func copyCredentialHeaders(headers http.Header, metadata map[string]string) {
	if metadata == nil || headers == nil {
		return
	}
	if value := strings.TrimSpace(headers.Get("Authorization")); value != "" {
		metadata["header_authorization"] = value
	}
	if value := strings.TrimSpace(headers.Get("Api-Key")); value != "" {
		metadata["header_api_key"] = value
	}
	if value := strings.TrimSpace(headers.Get("X-Api-Key")); value != "" {
		metadata["header_x_api_key"] = value
	}
	if value := strings.TrimSpace(headers.Get("X-Goog-Api-Key")); value != "" {
		metadata["header_x_goog_api_key"] = value
	}
}

func (l *limiter) logAuthDebug(info authDebugInfo) {
	if l == nil || !l.debugLogEnabled() {
		return
	}
	payload, errMarshal := json.Marshal(info)
	if errMarshal != nil {
		return
	}
	log.Printf("[%s] frontend_auth %s", pluginID, string(payload))
}
