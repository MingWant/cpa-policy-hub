package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func cloneHeader(values http.Header) http.Header {
	if values == nil {
		return nil
	}
	out := make(http.Header, len(values))
	for key, value := range values {
		out[key] = append([]string(nil), value...)
	}
	return out
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneIntSlice(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	return append([]int(nil), values...)
}

func cloneTimeWindowRules(values []timeWindowRule) []timeWindowRule {
	if len(values) == 0 {
		return nil
	}
	out := make([]timeWindowRule, len(values))
	for idx, value := range values {
		value.Days = cloneStringSlice(value.Days)
		out[idx] = value
	}
	return out
}

func cloneEndpointOverrideRules(values []endpointOverrideRule) []endpointOverrideRule {
	if len(values) == 0 {
		return nil
	}
	out := make([]endpointOverrideRule, len(values))
	for idx, value := range values {
		value.Keys = cloneStringSlice(value.Keys)
		value.Providers = cloneStringSlice(value.Providers)
		value.Models = cloneStringSlice(value.Models)
		value.RequestedModels = cloneStringSlice(value.RequestedModels)
		value.SourceFormats = cloneStringSlice(value.SourceFormats)
		value.ToFormats = cloneStringSlice(value.ToFormats)
		value.RequestPaths = cloneStringSlice(value.RequestPaths)
		value.Interfaces = cloneStringSlice(value.Interfaces)
		out[idx] = value
	}
	return out
}

func cloneRequestPolicyAction(action requestPolicyAction) requestPolicyAction {
	action.SetHeaders = cloneStringMap(action.SetHeaders)
	action.DeleteHeaders = cloneStringSlice(action.DeleteHeaders)
	action.SetJSON = cloneAnyMap(action.SetJSON)
	action.DeleteJSON = cloneStringSlice(action.DeleteJSON)
	action.Metadata = cloneAnyMap(action.Metadata)
	return action
}

func cloneResponsePolicyAction(action responsePolicyAction) responsePolicyAction {
	action.SetHeaders = cloneStringMap(action.SetHeaders)
	action.DeleteHeaders = cloneStringSlice(action.DeleteHeaders)
	action.SetJSON = cloneAnyMap(action.SetJSON)
	action.DeleteJSON = cloneStringSlice(action.DeleteJSON)
	action.Metadata = cloneAnyMap(action.Metadata)
	return action
}

func cloneErrorResponseRule(rule errorResponseRule) errorResponseRule {
	rule.JSON = cloneAnyMap(rule.JSON)
	rule.SetHeaders = cloneStringMap(rule.SetHeaders)
	rule.UpstreamStatuses = cloneIntSlice(rule.UpstreamStatuses)
	return rule
}

func cloneKeyRule(rule keyRule) keyRule {
	rule.AllowedModels = cloneStringSlice(rule.AllowedModels)
	rule.DeniedModels = cloneStringSlice(rule.DeniedModels)
	rule.AllowedProviders = cloneStringSlice(rule.AllowedProviders)
	rule.DeniedProviders = cloneStringSlice(rule.DeniedProviders)
	rule.TimeWindows = cloneTimeWindowRules(rule.TimeWindows)
	rule.EndpointOverrides = cloneEndpointOverrideRules(rule.EndpointOverrides)
	rule.Request = cloneRequestPolicyAction(rule.Request)
	rule.Response = cloneResponsePolicyAction(rule.Response)
	rule.ErrorResponse = cloneErrorResponseRule(rule.ErrorResponse)
	rule.Metadata = cloneStringMap(rule.Metadata)
	return rule
}

func cloneKeyRuleMap(values map[string]keyRule) map[string]keyRule {
	if values == nil {
		return map[string]keyRule{}
	}
	out := make(map[string]keyRule, len(values))
	for key, value := range values {
		out[key] = cloneKeyRule(value)
	}
	return out
}

func cloneUsageEvents(values []usageEvent) []usageEvent {
	if len(values) == 0 {
		return nil
	}
	return append([]usageEvent(nil), values...)
}

func clonePolicyEvents(values []policyEvent) []policyEvent {
	if len(values) == 0 {
		return nil
	}
	return append([]policyEvent(nil), values...)
}

func clonePersistedState(state persistedState) persistedState {
	return persistedState{
		Keys:      cloneKeyRuleMap(state.Keys),
		Usage:     cloneUsageMap(state.Usage),
		Events:    cloneUsageEvents(state.Events),
		PolicyLog: clonePolicyEvents(state.PolicyLog),
		Policies:  cloneUsageMap(state.Policies),
		Active:    cloneIntMap(state.Active),
		UpdatedAt: state.UpdatedAt,
	}
}

func (l *limiter) refreshRuntimeSnapshotLocked() {
	if l == nil {
		return
	}
	configured := cloneKeyRuleMap(l.configuredKeys)
	managed := cloneKeyRuleMap(l.state.Keys)
	merged := make(map[string]keyRule, len(configured)+len(managed))
	credentialIndex := make(map[string]string, len(configured)+len(managed))
	for id, rule := range configured {
		merged[id] = rule
		if validSHA256Hash(rule.KeyHash) {
			credentialIndex[normalizeHash(rule.KeyHash)] = id
		}
	}
	for id, rule := range managed {
		merged[id] = rule
		if validSHA256Hash(rule.KeyHash) {
			credentialIndex[normalizeHash(rule.KeyHash)] = id
		}
	}
	l.credentialIndex = cloneStringMap(credentialIndex)
	snapshot := &runtimeSnapshot{
		cfg:             l.cfg,
		keyRules:        merged,
		credentialIndex: credentialIndex,
		configLoadError: l.configLoadError,
		configuredCount: len(configured),
		managedCount:    len(managed),
	}
	snapshot.capabilities = computeRuntimeCapabilities(snapshot.cfg, configured, managed)
	l.snapshot.Store(snapshot)
}

func (l *limiter) currentSnapshot() *runtimeSnapshot {
	if l == nil {
		return nil
	}
	if snapshot := l.snapshot.Load(); snapshot != nil {
		return snapshot
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if snapshot := l.snapshot.Load(); snapshot != nil {
		return snapshot
	}
	l.refreshRuntimeSnapshotLocked()
	return l.snapshot.Load()
}

func (l *limiter) rebuildCredentialIndexLocked() {
	l.refreshRuntimeSnapshotLocked()
}

func (l *limiter) markDirtyLocked() {
	if l != nil {
		l.dirty = true
	}
}

func (l *limiter) prepareStateSaveLocked() (string, persistedState, bool) {
	if l == nil || !l.dirty {
		return "", persistedState{}, false
	}
	l.state.UpdatedAt = time.Now().UTC()
	path := l.cfg.StoragePath
	snapshot := clonePersistedState(l.state)
	l.dirty = false
	return path, snapshot, true
}

func (l *limiter) flushStateNow() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	path, snapshot, ok := l.prepareStateSaveLocked()
	l.mu.Unlock()
	if !ok {
		return nil
	}
	if errSave := saveState(path, snapshot); errSave != nil {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
		return errSave
	}
	return nil
}

func (l *limiter) requestStateSave() {
	if l == nil || l.saveSignal == nil {
		return
	}
	select {
	case l.saveSignal <- struct{}{}:
	default:
	}
}

func (l *limiter) startStateSaver() {
	if l == nil || l.saveSignal == nil || l.stopSignal == nil {
		return
	}
	go func() {
		const debounce = 250 * time.Millisecond
		var (
			timer   *time.Timer
			timerCh <-chan time.Time
		)
		stopTimer := func() {
			if timer == nil {
				return
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer = nil
			timerCh = nil
		}
		for {
			select {
			case <-l.saveSignal:
				if timer == nil {
					timer = time.NewTimer(debounce)
				} else {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(debounce)
				}
				timerCh = timer.C
			case <-timerCh:
				stopTimer()
				_ = l.flushStateNow()
			case <-l.stopSignal:
				stopTimer()
				_ = l.flushStateNow()
				return
			}
		}
	}()
}

func (l *limiter) shutdown() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stopSignal)
	})
}

func (l *limiter) listKeysLocked() []keyListItem {
	keys := make([]keyListItem, 0, len(l.configuredKeys)+len(l.state.Keys))
	for _, rule := range l.configuredKeys {
		if override, exists := l.state.Keys[rule.ID]; exists {
			override.Source = "override"
			if override.KeyFingerprint == "" {
				override.KeyFingerprint = rule.KeyFingerprint
			}
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
