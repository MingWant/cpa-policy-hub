package main

import (
	"bytes"
	"encoding/json"
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

func (l *limiter) saveStateLocked() error {
	l.state.UpdatedAt = time.Now().UTC()
	return saveState(l.cfg.StoragePath, l.state)
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
