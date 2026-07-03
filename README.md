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
make build-linux
```

Manual equivalents:

```bash
mkdir -p dist
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -trimpath -ldflags="-s -w" -o dist/cpa-policy-hub.so .
```

Use `.so` on Linux, `.dylib` on macOS, or `.dll` on Windows. The plugin requires CGO because it is built as a dynamic library.

## Recommended deployment order

1. Build `cpa-policy-hub.so` on the target Linux server.
2. Put it under CPA's plugin directory, for example `/home/docker/CLIProxyAPI/plugins/cpa-policy-hub.so`.
3. If CPA runs in Docker, mount the host plugin directory into the container:

   ```yaml
   volumes:
     - ./plugins:/CLIProxyAPI/plugins
   ```

4. Start with the safe config below. Confirm `/status` reports `traffic_enabled: false`.
5. Only then switch to advanced takeover mode if you want this plugin to authenticate/manage existing CPA `api-keys`.

Server safety notes:

- Keep `dry_run: true` while testing new policies. In dry-run mode request/response mutations and interface overrides are not applied to live traffic.
- Do not use `allowed_providers` unless your model names include a provider prefix such as `openai/gpt-4.1` or the request path makes the provider unambiguous. If a provider allow-list is configured and the provider cannot be determined, the plugin rejects the request.
- Policy request mutations intentionally cannot set or delete sensitive headers such as `Authorization`, `X-Api-Key`, `X-Goog-Api-Key`, `Cookie`, `Host`, or `Proxy-Authorization`.
- The management page saves runtime key overrides to `storage_path`; it does not rewrite CPA `config.yaml`.
- When `manage_config_api_keys: true` is enabled, the plugin automatically preserves the original client credential so CPA's downstream passthrough path still receives an API key after plugin authentication.

## Final server-ready notes

This build is intended to be safe for server use with a conservative workflow:

1. Start in management-only mode with `traffic_enabled: false`.
2. Switch takeover mode on with `dry_run: true` and verify `/policy-log`.
3. Switch `dry_run: false` only after auth, quota, provider/model limits, and interface overrides look correct.

The embedded UI can manage runtime key overrides including model/provider limits, hourly limits, time windows, request/response rewrites, and friendly upstream error messages. These runtime overrides are stored in `storage_path` and do not edit CPA's `config.yaml`.

Important behavior:

- PATCH key operations preserve advanced fields that a simple client/UI omits.
- `dry_run: true` prevents request/response mutations and interface override headers from being applied.
- Per-key `error_response` rewrites upstream responses whose body looks like an error. The current CPA SDK response interceptor payload does not expose HTTP status in this plugin path, so status-only matching is not relied on.

## Config

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    cpa-policy-hub:
      enabled: true
      priority: 100
      storage_path: "cpa-policy-hub-state.json"

      # Safe default: management UI only. The plugin does not touch normal CPA traffic.
      traffic_enabled: false
      exclusive: false
      manage_config_api_keys: false
      fail_closed: false
      dry_run: true
      expose_limit_headers: false

      default_allowed_models: ["*"]
      default_daily_token_limit: 0
      default_monthly_token_limit: 0
      default_request_limit_per_minute: 0

      auth:
        exclusive: false
        keys: []

      pricing: []
      policies: []
      endpoint_overrides: []
```

With this default config, the plugin only registers its Management API/resource page. It does not authenticate, intercept, mutate, rate-limit, or record normal CPA traffic.

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

### Manage CPAMC `api-keys` directly

Advanced takeover mode only. First verify the safe management-only config above. Then set `traffic_enabled: true` and `manage_config_api_keys: true` to let the plugin read the top-level CPA/CPAMC `api-keys` from `config.yaml`, hash them internally, and apply plugin limits/policies to them. `auth.exclusive: true` makes the plugin the frontend authenticator for the same client keys; a wrong config can block calls.

```yaml
api-keys:
  - "sk-client-a"
  - "sk-client-b"

plugins:
  enabled: true
  dir: "plugins"
  configs:
    cpa-policy-hub:
      enabled: true
      priority: 1
      storage_path: "cpa-policy-hub-state.json"
      traffic_enabled: true
      config_path: "config.yaml"
      manage_config_api_keys: true
      # Automatically enabled by manage_config_api_keys; explicit true is also OK.
      preserve_client_credentials: true
      fail_closed: false
      default_daily_token_limit: 100000
      default_monthly_token_limit: 1000000
      default_request_limit_per_minute: 60
      default_allowed_models: ["*"]
      auth:
        exclusive: true
```

  If the CPA process cannot find `config.yaml`, set `config_path` to the path visible inside the running CPA process/container. For Docker with `/CLIProxyAPI` as the container workdir, use `/CLIProxyAPI/config.yaml`; do not use the host path unless CPA runs directly on the host. See `examples/takeover.config.yaml` for a complete takeover-mode example.

Open the embedded management page at:

```text
http://<cpa-host>:<api-port>/v0/resource/plugins/cpa-policy-hub/index.html
```

The resource page loads without a management header. Enter CPA's management key in the page; all data calls then use `Authorization: Bearer <management-key>` against `/v0/management/plugins/cpa-policy-hub/...`.

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

The embedded browser UI is available at `/v0/resource/plugins/cpa-policy-hub/index.html`.

The UI includes:

- Status cards for traffic mode and key counts
- Table-based key browsing
- Form-based managed key creation/editing/deletion
- Form-based runtime overrides for imported CPA `api-keys`
- Key usage, policy usage, and active counters
- Usage events and policy log
- Reset/export/import tools
- YAML config builder

The page itself is a static plugin resource and does not embed credentials. All data reads/writes go through `/v0/management/plugins/cpa-policy-hub/...`; if the current CPAMC/session cannot call the Management API, the UI will show an authorization or connectivity failure.

When `manage_config_api_keys: true` is enabled, top-level CPA `api-keys` show up as `config` keys. Editing one in the UI saves a runtime override to `cpa-policy-hub-state.json`; it does not rewrite CPA `config.yaml`. Deleting that override makes the key fall back to the original `config.yaml` settings.

Static config such as `pricing` and `policies` is still applied from CPA `config.yaml`. The UI's Config Builder generates YAML snippets; copy them into `config.yaml` and restart CPA. Runtime state operations such as managed keys, imported-key overrides, reset, export, and import are saved by the plugin directly.

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
    - "https://raw.githubusercontent.com/MingWant/cpa-policy-hub/main/registry.json"
  configs:
    cpa-policy-hub:
      enabled: true
      priority: 100
      traffic_enabled: false
      manage_config_api_keys: false
      fail_closed: false
      dry_run: true
      auth:
        exclusive: false
        keys: []
      policies: []
```

Then install/update the plugin from CPAMC's plugin store page. This keeps the plugin lifecycle independent from official CPA binary updates.
