package main

import "strings"

func normalizeAnyMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out
	default:
		return nil
	}
}

func mapKeys(values map[string]any) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	return out
}

func accessMetadataMap(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	if access := normalizeAnyMap(metadata["accessMetadata"]); access != nil {
		return access
	}
	if access := normalizeAnyMap(metadata["access_metadata"]); access != nil {
		return access
	}
	return nil
}

func (r endpointOverrideRule) matchName() string {
	name := strings.TrimSpace(r.Name)
	if name != "" {
		return name
	}
	forced := normalizeInterface(r.ForceInterface)
	if forced != "" {
		return forced
	}
	if len(r.Interfaces) > 0 {
		return normalizeInterface(r.Interfaces[0])
	}
	return "preserve"
}

func providerFromFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "openai", "openai-response":
		return "openai"
	case "claude":
		return "claude"
	case "gemini":
		return "gemini"
	case "codex":
		return "codex"
	case "antigravity":
		return "antigravity"
	default:
		return strings.ToLower(strings.TrimSpace(format))
	}
}

func normalizeInterface(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "/v1/")
	value = strings.TrimPrefix(value, "/")
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, "/", "_")
	switch value {
	case "", "passthrough", "preserve":
		return value
	case "chat", "chat_completions", "chat_complete", "chat_completion", "completions":
		return "chat_completions"
	case "message", "messages":
		return "messages"
	case "response", "responses":
		return "responses"
	case "responses_compact", "response_compact":
		return "responses_compact"
	default:
		return value
	}
}

func keyIDFromMetadata(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	if access := accessMetadataMap(metadata); access != nil {
		if keyID := stringFromAny(access["key_id"]); keyID != "" {
			return keyID
		}
	}
	if keyID := stringFromAny(metadata["key_id"]); keyID != "" {
		return keyID
	}
	return ""
}

func stringFromMetadata(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	if access := accessMetadataMap(metadata); access != nil {
		if value := stringFromAny(access[key]); value != "" {
			return value
		}
	}
	return stringFromAny(metadata[key])
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	default:
		return ""
	}
}

func stringListMatches(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	value = strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == value || wildcardMatch(pattern, value) {
			return true
		}
	}
	return false
}

func pathListMatches(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	value = normalizeEndpointPath(value)
	for _, pattern := range patterns {
		pattern = normalizeEndpointPath(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == value || strings.HasSuffix(value, pattern) || wildcardMatch(pattern, value) {
			return true
		}
	}
	return false
}

func normalizeEndpointPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimPrefix(path, "/v1")
	if path == "" {
		return "/"
	}
	return path
}

func wildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	return strings.HasSuffix(value[pos:], last)
}

func modelAllowed(model string, allowed []string) bool {
	if len(allowed) == 0 || strings.TrimSpace(model) == "" {
		return true
	}
	model = strings.ToLower(strings.TrimSpace(model))
	for _, pattern := range allowed {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == model {
			return true
		}
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(model, strings.TrimSuffix(pattern, "*")) {
			return true
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(model, strings.TrimPrefix(pattern, "*")) {
			return true
		}
	}
	return false
}
