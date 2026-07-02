package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

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
	if rule.KeyFingerprint == "" && rule.Key != "" {
		rule.KeyFingerprint = maskAPIKey(rule.Key)
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
		{headers.Get("Api-Key"), "api-key"},
		{headers.Get("X-Goog-Api-Key"), "x-goog-api-key"},
		{headers.Get("X-Api-Key"), "x-api-key"},
		{firstQuery(query, "api_key"), "query-api-key"},
		{firstQuery(query, "key"), "query-key"},
		{firstQuery(query, "token"), "query-token"},
		{firstQuery(query, "access_token"), "query-access-token"},
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

func maskAPIKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return key[:1] + "..." + key[len(key)-1:]
	}
	prefixLen := 4
	if strings.HasPrefix(strings.ToLower(key), "sk-") && len(key) >= 7 {
		prefixLen = 6
	}
	if prefixLen > len(key)-4 {
		prefixLen = len(key) / 2
	}
	return key[:prefixLen] + "..." + key[len(key)-4:]
}
