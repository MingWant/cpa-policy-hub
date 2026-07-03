package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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
	if resolved, ok := currentLimiter.resolveKeyID(keyID); ok {
		keyID = resolved
	}
	cost := currentLimiter.usageCost(record)
	currentLimiter.mu.Lock()
	failClosed := currentLimiter.cfg.FailClosed
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
	currentLimiter.markDirtyLocked()
	currentLimiter.mu.Unlock()
	if failClosed {
		if errSave := currentLimiter.flushStateNow(); errSave != nil {
			return nil, errSave
		}
	} else {
		currentLimiter.requestStateSave()
	}
	return okEnvelope(struct{}{})
}
