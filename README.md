# CPA Policy Hub Plugin

CPA Policy Hub is a dynamic CLIProxyAPI plugin for gateway-side policy customization. It keeps the original API key/token limiter behavior, but the public direction is now a broader policy engine for auth, quotas, usage accounting, endpoint/interface override, and future request/response rewrite rules.

The runtime plugin ID is `cpa-policy-hub`; legacy management routes under `api-key-token-limiter` are still registered for compatibility.

For portable installation/update across CPA systems, publish the plugin through a plugin-store registry. See `RELEASE.md` and `registry.example.json`.

## Current features

- Frontend API key authentication
- Static and managed API keys
- Per-key daily/monthly/total token limits
- Per-key request-per-minute limits
- Per-key model allow lists
- Usage counters and recent usage events
- CPAMC-compatible Management API routes
- Conditional upstream interface override rules
- New `auth` and `policies` config blocks as aliases for the initial policy engine

## Build

From this repository root:

```bash
go build -buildmode=c-shared -o dist/cpa-policy-hub.dll .
```

Use `.so` on Linux or `.dylib` on macOS.

## Config

```yaml
plugins:
  enabled: true
  dir: "examples/plugin/bin"
  configs:
    cpa-policy-hub:
      enabled: true
      priority: 1
      storage_path: "cpa-policy-hub-state.json"
      fail_closed: true
      dry_run: false
      expose_limit_headers: false

      pricing:
        - model: "gpt-5*"
          input_per_1m: 1.25
          output_per_1m: 10
          reasoning_per_1m: 10
          cached_input_per_1m: 0.125
          estimated_input_tokens: 2000
          estimated_output_tokens: 1000

      auth:
        exclusive: true
        keys:
          - id: "dev"
            name: "Development key"
            key: "dev-secret-change-me"
            tenant: "team-a"
            plan: "basic"
            daily_token_limit: 10000
            request_limit_per_minute: 10
            allowed_models: ["*"]

      policies:
        - name: "force-responses-for-dev"
          deny: false
          message: "This request is blocked by CPA Policy Hub"
          match:
            keys: ["dev"]
            providers: ["openai"]
            models: ["some-responses-only-model"]
            request_paths: ["/chat/completions"]
          interface:
            force_interface: "responses"
          quota:
            scope: "tenant"
            daily_token_limit: 100000
            monthly_token_limit: 1000000
            daily_cost_limit: 5
            monthly_cost_limit: 100
            request_limit_per_minute: 60
            concurrency_limit: 3
            daily_request_limit: 1000
          request:
            set_headers:
              X-Team: "team-a"
            delete_headers: ["X-Debug"]
            max_tokens:
              max: 4096
            temperature:
              min: 0
              max: 1
            reasoning_effort:
              deny: ["high", "xhigh"]
              replace: "medium"
            set_json:
              metadata.policy: "force-responses-for-dev"
            delete_json: ["debug"]
          response:
            delete_headers: ["X-Internal-Debug"]
            set_headers:
              X-Policy-Hub: "matched"
            delete_json: ["debug", "internal"]
```

Prefer `key_hash` over plaintext `key` in production. Hashes are SHA-256 values with an optional `sha256:` prefix.

## Legacy config compatibility

The old flat config remains supported:

```yaml
plugins:
  configs:
    api-key-token-limiter:
      enabled: true
      exclusive: true
      storage_path: "api-key-token-limiter-state.json"
      default_daily_token_limit: 100000
      default_monthly_token_limit: 1000000
      default_request_limit_per_minute: 60
      default_allowed_models: ["gpt-*", "claude-*"]
      endpoint_overrides:
        - name: "force-openai-compatible-models-to-responses"
          providers: ["openai"]
          models: ["some-responses-only-model"]
          request_paths: ["/chat/completions"]
          force_interface: "responses"
      keys:
        - id: "dev"
          key: "dev-secret-change-me"
          daily_token_limit: 10000
          request_limit_per_minute: 10
          allowed_models: ["*"]
```

For new installs, prefer `cpa-policy-hub` and the `auth` / `policies` blocks.

## Policy blocks

The policy engine currently supports interface overrides plus request/response mutation actions:

```yaml
policies:
  - name: "block-public-high-cost-models"
    deny: true
    message: "This key cannot use high-cost models"
    match:
      keys: ["public-*"]
      models: ["gpt-5*", "claude-opus*"]

  - name: "responses-only-model"
    match:
      keys: ["dev"]
      providers: ["openai"]
      models: ["my-responses-only-model"]
      request_paths: ["/chat/completions"]
    interface:
      force_interface: "responses"
    quota:
      scope: "policy"
      daily_token_limit: 100000
      monthly_token_limit: 1000000
      total_token_limit: 5000000
      daily_cost_limit: 5
      monthly_cost_limit: 100
      total_cost_limit: 500
      request_limit_per_minute: 60
      concurrency_limit: 3
      daily_request_limit: 1000
      monthly_request_limit: 30000
    request:
      set_headers:
        X-Team: "team-a"
      delete_headers: ["X-Debug"]
      set_model: "my-upstream-model"
      set_service_tier: "default"
      max_tokens:
        max: 4096
      temperature:
        min: 0
        max: 1
      reasoning_effort:
        deny: ["high", "xhigh"]
        replace: "medium"
      set_json:
        metadata.policy: "responses-only-model"
      delete_json: ["debug"]
    response:
      set_headers:
        X-Policy-Hub: "responses-only-model"
      delete_headers: ["X-Internal-Debug"]
      set_json:
        metadata.policy: "responses-only-model"
      delete_json: ["debug", "internal"]
```

JSON paths use dot notation, for example `reasoning.effort` or `metadata.policy`.

## Policy-level quotas

`policies[].quota` adds quota counters above the key-level limits. Supported scopes:

- `policy` or `global`: one shared counter for the policy
- `tenant`: one counter per key tenant plus policy
- `plan`: one counter per key plan plus policy
- `key`: one counter per key plus policy

Supported limits:

- `daily_token_limit`
- `monthly_token_limit`
- `total_token_limit`
- `request_limit_per_minute`
- `concurrency_limit`
- `daily_request_limit`
- `monthly_request_limit`
- `total_request_limit`
- `daily_cost_limit`
- `monthly_cost_limit`
- `total_cost_limit`

Example:

```yaml
policies:
  - name: "team-a-shared-budget"
    match:
      keys: ["team-a-*"]
      models: ["gpt-*"]
    quota:
      scope: "tenant"
      daily_token_limit: 100000
      monthly_token_limit: 1000000
      daily_cost_limit: 5
      monthly_cost_limit: 100
      request_limit_per_minute: 120
      concurrency_limit: 10
```

Policy counters are returned from:

- `GET /v0/management/plugins/cpa-policy-hub/usage`

## Concurrency quotas

Use `concurrency_limit` to cap active in-flight requests for a policy scope:

```yaml
policies:
  - name: "team-a-concurrency"
    match:
      keys: ["team-a-*"]
    quota:
      scope: "tenant"
      concurrency_limit: 10
```

The counter is incremented during frontend auth and released when CPA publishes the final usage record. If the process exits before usage is recorded, active counters may remain in the state file and can be reset by editing the `active` map or rotating the state file.

Current active counters are returned from:

- `GET /v0/management/plugins/cpa-policy-hub/usage`

## Pricing and cost quotas

Define `pricing` rules to calculate cost from usage records:

```yaml
pricing:
  - model: "gpt-5*"
    input_per_1m: 1.25
    output_per_1m: 10
    reasoning_per_1m: 10
    cached_input_per_1m: 0.125
    flat_request_cost: 0
    estimated_input_tokens: 2000
    estimated_output_tokens: 1000
```

Cost is recorded on key usage and policy usage counters. `estimated_*` values are used during frontend auth to conservatively reject requests before the final usage record is available.

Then add cost limits to a policy quota:

```yaml
policies:
  - name: "team-a-cost-budget"
    match:
      keys: ["team-a-*"]
    quota:
      scope: "tenant"
      daily_cost_limit: 5
      monthly_cost_limit: 100
```

## Deny, dry-run, and audit log

Set `deny: true` on a policy to reject matching authenticated requests during frontend auth. The frontend auth API currently only supports an authenticated/unauthenticated decision, so deny responses use CPA's normal auth failure behavior.

Use `dry_run: true` to test policy behavior without enforcing deny or applying request/response mutations:

```yaml
plugins:
  configs:
    cpa-policy-hub:
      dry_run: true
      policies:
        - name: "would-block-public-high-cost-models"
          deny: true
          match:
            keys: ["public-*"]
            models: ["gpt-5*"]
```

Policy matches are recorded in the state file and can be queried through:

- `GET /v0/management/plugins/cpa-policy-hub/policy-log?limit=100`

Event actions include:

- `deny`
- `would_deny`
- `mutate_request`
- `would_mutate_request`
- `mutate_response`
- `would_mutate_response`

## Endpoint / Interface Overrides

Rules are evaluated in this order:

1. The matched key's `endpoint_overrides`
2. Global `endpoint_overrides`
3. `policies[].interface` rules converted during config load

The first matching rule wins. `preserve: true` keeps CPA passthrough behavior. Otherwise `force_interface` can be one of:

- `passthrough` / `preserve`
- `chat_completions` for upstream `/chat/completions`
- `responses` for upstream `/responses`
- `responses_compact` for upstream `/responses/compact` when non-streaming
- `messages` is accepted in config for policy matching, but only providers whose executors support a mutable endpoint can honor it directly

Rule conditions support exact match and `*` wildcards:

- `keys`
- `providers`
- `models`
- `requested_models`
- `source_formats`
- `to_formats`
- `request_paths`

This plugin emits an internal `X-CLIProxy-Force-Interface` header after auth. The OpenAI-compatible executor honors `chat_completions`, `responses`, and `responses_compact`.

## Management API

Authenticated routes are exposed under `/v0/management`:

- `GET /v0/management/plugins/cpa-policy-hub/status`
- `GET /v0/management/plugins/cpa-policy-hub/keys`
- `POST /v0/management/plugins/cpa-policy-hub/keys`
- `PATCH /v0/management/plugins/cpa-policy-hub/keys`
- `DELETE /v0/management/plugins/cpa-policy-hub/keys?id=<key-id>`
- `GET /v0/management/plugins/cpa-policy-hub/usage`
- `GET /v0/management/plugins/cpa-policy-hub/events?limit=100`
- `GET /v0/management/plugins/cpa-policy-hub/policy-log?limit=100`
- `POST /v0/management/plugins/cpa-policy-hub/reset`
- `GET /v0/management/plugins/cpa-policy-hub/export`
- `POST /v0/management/plugins/cpa-policy-hub/import`

Legacy `/v0/management/plugins/api-key-token-limiter/...` routes are also available.

The embedded browser UI is available at `/v0/resource/plugins/cpa-policy-hub/status`.

The UI includes:

- Dashboard metrics
- Managed key creation/deletion
- Key usage, policy usage, and active counters
- Usage events and policy log
- Reset/export/import tools
- YAML config builder

The page itself is a static plugin resource and does not embed credentials. All data reads/writes go through `/v0/management/plugins/cpa-policy-hub/...`; if the current CPAMC/session cannot call the Management API, the UI will show an authorization or connectivity failure.

Static config such as `pricing`, `policies`, and `auth.keys` is still applied from CPA `config.yaml`. The UI's Config Builder generates YAML snippets; copy them into `config.yaml` and restart CPA. Runtime state operations such as managed keys, reset, export, and import are saved by the plugin directly.

### Reset counters

Reset all active concurrency counters:

```json
{"target":"active"}
```

Reset one policy counter:

```json
{"target":"policy_usage","id":"tenant:team-a:team-a-shared-budget"}
```

Supported reset targets:

- `active`
- `usage` / `key_usage`
- `policy_usage` / `policy_quota`
- `events`
- `policy_log`
- `all_counters`

### Export/import state

Export returns the current persisted state:

```text
GET /v0/management/plugins/cpa-policy-hub/export
```

Import can merge or replace state:

```json
{
  "replace": false,
  "state": {
    "keys": {},
    "usage": {},
    "policies": {},
    "active": {}
  }
}
```

## Portable installation through a plugin store

After publishing release artifacts and a registry JSON, add the registry URL to any CPA instance:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  store-sources:
    - "https://raw.githubusercontent.com/YOUR_ORG/api-key-token-limiter-plugin/main/registry.json"
  configs:
    cpa-policy-hub:
      enabled: true
      priority: 1
      auth:
        exclusive: true
```

Then install/update the plugin from CPAMC's plugin store page. This keeps the plugin lifecycle independent from official CPA binary updates.
