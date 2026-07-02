package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func applyRequestPolicy(action requestPolicyAction, headers http.Header, clearHeaders *[]string, body *[]byte) (bool, error) {
	changed := applyHeaderPolicy(action.SetHeaders, action.DeleteHeaders, headers, clearHeaders, protectedRequestHeaders)
	if strings.TrimSpace(action.SetModel) != "" {
		if errSet := setJSONPath(body, "model", strings.TrimSpace(action.SetModel)); errSet != nil {
			return changed, errSet
		}
		changed = true
	}
	if strings.TrimSpace(action.SetServiceTier) != "" {
		if errSet := setJSONPath(body, "service_tier", strings.TrimSpace(action.SetServiceTier)); errSet != nil {
			return changed, errSet
		}
		changed = true
	}
	if action.MaxTokens != nil {
		updated, errClamp := clampJSONInt(body, []string{"max_tokens", "max_completion_tokens"}, *action.MaxTokens)
		if errClamp != nil {
			return changed, errClamp
		}
		changed = changed || updated
	}
	if action.Temperature != nil {
		updated, errClamp := clampJSONFloat(body, "temperature", *action.Temperature)
		if errClamp != nil {
			return changed, errClamp
		}
		changed = changed || updated
	}
	if len(action.ReasoningEffort.Deny) > 0 || strings.TrimSpace(action.ReasoningEffort.Replace) != "" {
		updated, errReasoning := applyReasoningEffortPolicy(body, action.ReasoningEffort)
		if errReasoning != nil {
			return changed, errReasoning
		}
		changed = changed || updated
	}
	updated, errJSON := applyJSONPolicy(action.SetJSON, action.DeleteJSON, body)
	return changed || updated, errJSON
}

func requestPolicyConfigured(action requestPolicyAction) bool {
	return len(action.SetHeaders) > 0 || len(action.DeleteHeaders) > 0 || len(action.SetJSON) > 0 || len(action.DeleteJSON) > 0 || strings.TrimSpace(action.SetModel) != "" || strings.TrimSpace(action.SetServiceTier) != "" || action.MaxTokens != nil || action.Temperature != nil || len(action.ReasoningEffort.Deny) > 0 || strings.TrimSpace(action.ReasoningEffort.Replace) != ""
}

func applyResponsePolicy(action responsePolicyAction, headers http.Header, clearHeaders *[]string, body *[]byte) (bool, error) {
	changed := applyHeaderPolicy(action.SetHeaders, action.DeleteHeaders, headers, clearHeaders, protectedResponseHeaders)
	updated, errJSON := applyJSONPolicy(action.SetJSON, action.DeleteJSON, body)
	return changed || updated, errJSON
}

func responsePolicyConfigured(action responsePolicyAction) bool {
	return len(action.SetHeaders) > 0 || len(action.DeleteHeaders) > 0 || len(action.SetJSON) > 0 || len(action.DeleteJSON) > 0
}

func errorResponseConfigured(rule errorResponseRule) bool {
	return rule.StatusCode > 0 || strings.TrimSpace(rule.Message) != "" || strings.TrimSpace(rule.Body) != "" || len(rule.JSON) > 0 || len(rule.SetHeaders) > 0 || rule.HideUpstream
}

func applyCustomErrorResponse(rule errorResponseRule, headers *http.Header, clearHeaders *[]string, body *[]byte) bool {
	if !errorResponseConfigured(rule) || !upstreamBodyLooksLikeError(*body) {
		return false
	}
	if headers == nil {
		return false
	}
	for name, value := range rule.SetHeaders {
		name = strings.TrimSpace(name)
		if name == "" || protectedHeader(name, protectedResponseHeaders) {
			continue
		}
		headers.Set(name, value)
	}
	if len(rule.JSON) > 0 {
		payload := cloneAnyMap(rule.JSON)
		if _, exists := payload["error"]; !exists && strings.TrimSpace(rule.Message) != "" {
			payload["error"] = map[string]any{"message": strings.TrimSpace(rule.Message), "type": "policy_hub_error"}
		}
		if raw, errMarshal := json.Marshal(payload); errMarshal == nil {
			*body = raw
			headers.Set("Content-Type", "application/json; charset=utf-8")
			return true
		}
	}
	message := strings.TrimSpace(rule.Body)
	if message == "" {
		message = strings.TrimSpace(rule.Message)
	}
	if message == "" {
		message = "The upstream provider returned an error. Try a different model or contact the API administrator."
	}
	*body = []byte(`{"error":{"message":` + strconv.Quote(message) + `,"type":"policy_hub_error"}}`)
	headers.Set("Content-Type", "application/json; charset=utf-8")
	return true
}

func upstreamBodyLooksLikeError(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || len(trimmed) > maxAuthModelBodyBytes {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(trimmed, &payload) != nil {
		text := strings.ToLower(string(trimmed))
		return strings.Contains(text, "error") || strings.Contains(text, "exception") || strings.Contains(text, "rate limit")
	}
	if _, ok := payload["error"]; ok {
		return true
	}
	if _, ok := payload["errors"]; ok {
		return true
	}
	status := strings.ToLower(stringFromAny(payload["status"]))
	return status == "error" || status == "failed"
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func applyHeaderPolicy(setHeaders map[string]string, deleteHeaders []string, headers http.Header, clearHeaders *[]string, protected map[string]struct{}) bool {
	changed := false
	for name, value := range setHeaders {
		name = strings.TrimSpace(name)
		if name == "" || protectedHeader(name, protected) {
			continue
		}
		headers.Set(name, value)
		changed = true
	}
	for _, name := range deleteHeaders {
		name = strings.TrimSpace(name)
		if name == "" || protectedHeader(name, protected) {
			continue
		}
		*clearHeaders = append(*clearHeaders, name)
		changed = true
	}
	return changed
}

func protectedHeader(name string, protected map[string]struct{}) bool {
	if len(protected) == 0 {
		return false
	}
	_, ok := protected[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func applyJSONPolicy(setValues map[string]any, deletePaths []string, body *[]byte) (bool, error) {
	changed := false
	for path, value := range setValues {
		if errSet := setJSONPath(body, path, value); errSet != nil {
			return changed, errSet
		}
		changed = true
	}
	for _, path := range deletePaths {
		updated, errDelete := deleteJSONPath(body, path)
		if errDelete != nil {
			return changed, errDelete
		}
		changed = changed || updated
	}
	return changed, nil
}

func setJSONPath(body *[]byte, path string, value any) error {
	payload := map[string]any{}
	if len(bytes.TrimSpace(*body)) > 0 {
		if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return nil
	}
	current := payload
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok || next == nil {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
	return marshalJSONBody(body, payload)
}

func deleteJSONPath(body *[]byte, path string) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return false, nil
	}
	current := payload
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok || next == nil {
			return false, nil
		}
		current = next
	}
	last := parts[len(parts)-1]
	if _, exists := current[last]; !exists {
		return false, nil
	}
	delete(current, last)
	return true, marshalJSONBody(body, payload)
}

func clampJSONInt(body *[]byte, paths []string, clamp intClamp) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	changed := false
	for _, path := range paths {
		value, ok := jsonPathValue(payload, path)
		if !ok {
			continue
		}
		number, okNumber := numberToFloat64(value)
		if !okNumber {
			continue
		}
		clamped := int64(number)
		if clamp.Min > 0 && clamped < clamp.Min {
			clamped = clamp.Min
		}
		if clamp.Max > 0 && clamped > clamp.Max {
			clamped = clamp.Max
		}
		if float64(clamped) != number {
			if errSet := setJSONValue(payload, path, clamped); errSet != nil {
				return changed, errSet
			}
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	return true, marshalJSONBody(body, payload)
}

func clampJSONFloat(body *[]byte, path string, clamp floatClamp) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	value, ok := jsonPathValue(payload, path)
	if !ok {
		return false, nil
	}
	number, okNumber := numberToFloat64(value)
	if !okNumber {
		return false, nil
	}
	clamped := number
	if clamp.Min > 0 && clamped < clamp.Min {
		clamped = clamp.Min
	}
	if clamp.Max > 0 && clamped > clamp.Max {
		clamped = clamp.Max
	}
	if clamped == number {
		return false, nil
	}
	if errSet := setJSONValue(payload, path, clamped); errSet != nil {
		return false, errSet
	}
	return true, marshalJSONBody(body, payload)
}

func applyReasoningEffortPolicy(body *[]byte, policy reasoningEffortPolicy) (bool, error) {
	if len(bytes.TrimSpace(*body)) == 0 {
		return false, nil
	}
	payload := map[string]any{}
	if errUnmarshal := json.Unmarshal(*body, &payload); errUnmarshal != nil {
		return false, errUnmarshal
	}
	value, ok := jsonPathValue(payload, "reasoning.effort")
	if !ok {
		value, ok = jsonPathValue(payload, "thinking.effort")
	}
	if !ok {
		return false, nil
	}
	effort := strings.ToLower(strings.TrimSpace(stringFromAny(value)))
	if effort == "" || !stringListMatches(policy.Deny, effort) {
		return false, nil
	}
	replacement := strings.TrimSpace(policy.Replace)
	if replacement == "" {
		replacement = "medium"
	}
	if _, exists := jsonPathValue(payload, "reasoning.effort"); exists {
		if errSet := setJSONValue(payload, "reasoning.effort", replacement); errSet != nil {
			return false, errSet
		}
	} else if errSet := setJSONValue(payload, "thinking.effort", replacement); errSet != nil {
		return false, errSet
	}
	return true, marshalJSONBody(body, payload)
}

func jsonPathParts(path string) []string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return nil
	}
	rawParts := strings.Split(path, ".")
	parts := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func jsonPathValue(payload map[string]any, path string) (any, bool) {
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return nil, false
	}
	var current any = payload
	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func setJSONValue(payload map[string]any, path string, value any) error {
	parts := jsonPathParts(path)
	if len(parts) == 0 {
		return nil
	}
	current := payload
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok || next == nil {
			next = map[string]any{}
			current[part] = next
		}
		current = next
	}
	current[parts[len(parts)-1]] = value
	return nil
}

func marshalJSONBody(body *[]byte, payload map[string]any) error {
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return errMarshal
	}
	*body = raw
	return nil
}

func numberToFloat64(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case json.Number:
		parsed, errParse := typed.Float64()
		return parsed, errParse == nil
	default:
		return 0, false
	}
}
