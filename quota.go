package main

import (
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (l *limiter) ensureUsageLocked(keyID string) *usageCounter {
	if l.state.Usage == nil {
		l.state.Usage = map[string]*usageCounter{}
	}
	usage := l.state.Usage[keyID]
	if usage == nil {
		usage = &usageCounter{}
		l.state.Usage[keyID] = usage
	}
	ensureUsageMaps(usage)
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
	ctx := endpointOverrideContext{KeyID: keyID, Provider: record.Provider, Model: record.Model, RequestedModel: firstNonEmpty(record.Alias, record.Model)}
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
	ctx := endpointOverrideContext{KeyID: keyID, Provider: record.Provider, Model: record.Model, RequestedModel: firstNonEmpty(record.Alias, record.Model)}
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
	return pricing.cost(pluginapi.UsageDetail{InputTokens: pricing.EstimatedInput, OutputTokens: pricing.EstimatedOutput, ReasoningTokens: pricing.EstimatedReasoning})
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
