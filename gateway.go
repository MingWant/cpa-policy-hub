package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func interceptRequest(raw []byte) ([]byte, error) {
	if !currentLimiter.trafficConfigEnabled() {
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	}
	var req pluginapi.RequestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	headers := http.Header{}
	headers.Set("X-CLIProxy-Policy-Hub", pluginID)
	clearHeaders := []string{}
	body := append([]byte(nil), req.Body...)
	dryRun := currentLimiter.dryRun()
	ctx := requestPolicyContext(req)
	if !dryRun {
		applyClientCredentialPassthrough(req.Metadata, headers)
	}
	if rule, ok := currentLimiter.keyRuleByID(ctx.KeyID); ok {
		changed, errApply := applyRequestPolicy(rule.Request, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && rule.ID != "" && !dryRun {
			headers.Add("X-CLIProxy-Policy-Hub-Match", "key:"+rule.ID)
		}
	}
	for _, policy := range currentLimiter.matchingPolicies(ctx) {
		if policy.Deny {
			currentLimiter.recordPolicyEvent(policyEvent{At: time.Now().UTC(), Policy: policy.Name, Action: dryRunAction("would_deny", "deny", dryRun), KeyID: ctx.KeyID, Provider: ctx.Provider, Model: ctx.Model, RequestPath: ctx.RequestPath, DryRun: dryRun, Message: policy.denyMessage()})
		}
		changed, errApply := applyRequestPolicy(policy.Request, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && policy.Name != "" {
			currentLimiter.recordPolicyEvent(policyEvent{At: time.Now().UTC(), Policy: policy.Name, Action: dryRunAction("would_mutate_request", "mutate_request", dryRun), KeyID: ctx.KeyID, Provider: ctx.Provider, Model: ctx.Model, RequestPath: ctx.RequestPath, DryRun: dryRun})
			if !dryRun {
				headers.Add("X-CLIProxy-Policy-Hub-Match", policy.Name)
			}
		}
	}
	if dryRun {
		body = append([]byte(nil), req.Body...)
		clearHeaders = nil
		headers = http.Header{}
		headers.Set("X-CLIProxy-Policy-Hub-Dry-Run", "true")
	}
	if !dryRun && req.ToFormat != "" {
		if target, matched := currentLimiter.endpointOverride(req); matched != "" {
			if target != "" {
				headers.Set(interfaceOverrideHeader, target)
				headers.Set(interfaceOverrideMatchHeader, matched)
			}
		}
	}
	response := pluginapi.RequestInterceptResponse{Headers: headers, ClearHeaders: clearHeaders}
	if !bytes.Equal(body, req.Body) {
		response.Body = body
	}
	return okEnvelope(response)
}

func (l *limiter) keyRuleByID(keyID string) (keyRule, bool) {
	if l == nil || strings.TrimSpace(keyID) == "" {
		return keyRule{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.keyRuleByIDLocked(keyID)
}

func interceptResponse(raw []byte) ([]byte, error) {
	if !currentLimiter.trafficConfigEnabled() {
		return okEnvelope(pluginapi.ResponseInterceptResponse{})
	}
	var req pluginapi.ResponseInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	headers := http.Header{}
	clearHeaders := []string{}
	body := append([]byte(nil), req.Body...)
	dryRun := currentLimiter.dryRun()
	ctx := responsePolicyContext(req)
	if rule, ok := currentLimiter.keyRuleByID(ctx.KeyID); ok {
		if applyCustomErrorResponse(rule.ErrorResponse, &headers, &clearHeaders, &body) && rule.ID != "" && !dryRun {
			headers.Add("X-CLIProxy-Policy-Hub-Match", "key-error:"+rule.ID)
		}
		changed, errApply := applyResponsePolicy(rule.Response, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && rule.ID != "" && !dryRun {
			headers.Add("X-CLIProxy-Policy-Hub-Match", "key:"+rule.ID)
		}
	}
	for _, policy := range currentLimiter.matchingPolicies(ctx) {
		changed, errApply := applyResponsePolicy(policy.Response, headers, &clearHeaders, &body)
		if errApply != nil {
			return nil, errApply
		}
		if changed && policy.Name != "" {
			currentLimiter.recordPolicyEvent(policyEvent{At: time.Now().UTC(), Policy: policy.Name, Action: dryRunAction("would_mutate_response", "mutate_response", dryRun), KeyID: ctx.KeyID, Provider: ctx.Provider, Model: ctx.Model, RequestPath: ctx.RequestPath, DryRun: dryRun})
			if !dryRun {
				headers.Add("X-CLIProxy-Policy-Hub-Match", policy.Name)
			}
		}
	}
	if dryRun {
		body = append([]byte(nil), req.Body...)
		clearHeaders = nil
		headers = http.Header{}
		headers.Set("X-CLIProxy-Policy-Hub-Dry-Run", "true")
	}
	currentLimiter.mu.Lock()
	expose := currentLimiter.cfg.ExposeLimitHeaders
	currentLimiter.mu.Unlock()
	if expose {
		headers.Set("X-CLIProxy-Policy-Hub", pluginID)
	}
	response := pluginapi.ResponseInterceptResponse{Headers: headers, ClearHeaders: clearHeaders}
	if !bytes.Equal(body, req.Body) {
		response.Body = body
	}
	return okEnvelope(response)
}
