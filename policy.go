package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (l *limiter) endpointOverride(req pluginapi.RequestInterceptRequest) (string, string) {
	if l == nil {
		return "", ""
	}
	snapshot := l.currentSnapshot()
	if snapshot == nil {
		return "", ""
	}
	keyID := keyIDFromMetadata(req.Metadata)
	var rules []endpointOverrideRule
	if keyID != "" {
		if rule, ok := snapshot.keyRules[keyID]; ok {
			rules = append(rules, rule.EndpointOverrides...)
		}
	}
	rules = append(rules, snapshot.cfg.EndpointOverrides...)
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
	snapshot := l.currentSnapshot()
	if snapshot == nil {
		return nil
	}
	policies := snapshot.cfg.Policies
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

func applyClientCredentialPassthrough(metadata map[string]any, headers http.Header) bool {
	credential := stringFromMetadata(metadata, "client_credential")
	if credential == "" {
		return false
	}
	source := strings.ToLower(stringFromMetadata(metadata, "client_credential_source"))
	switch source {
	case "api-key":
		headers.Set("Api-Key", credential)
	case "x-api-key":
		headers.Set("X-Api-Key", credential)
	case "x-goog-api-key":
		headers.Set("X-Goog-Api-Key", credential)
	case "query-api-key", "query-key", "query-token", "query-access-token", "query-auth-token":
		headers.Set("Authorization", "Bearer "+credential)
	default:
		headers.Set("Authorization", "Bearer "+credential)
	}
	return true
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
