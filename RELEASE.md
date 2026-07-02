# Releasing CPA Policy Hub as a portable CPA plugin

The goal is to publish this plugin once and let any CLIProxyAPI/CPAMC instance install or update it from a plugin store registry instead of copying DLL/SO/DYLIB files manually after each official CPA update.

## Recommended distribution model

Use CLIProxyAPI's built-in plugin store support:

1. Build one artifact per target platform.
2. Upload those artifacts to a stable release location, usually GitHub Releases.
3. Publish a `registry.json` that points to those artifacts and their SHA-256 checksums.
4. Add the registry URL to each CPA instance under `plugins.store-sources`.
5. Install or update from CPAMC's plugin store page or the Management API.

This decouples plugin releases from official CPA releases. When CPA updates, the plugin remains installed under the configured `plugins.dir`; when the plugin updates, CPAMC can detect and install the plugin update from the registry.

The recommended repository name is `cpa-policy-hub`. The plugin's runtime ID is `cpa-policy-hub`.

## Artifact names

Each release artifact should be a zip containing exactly one dynamic library for that platform:

- `cpa-policy-hub.dll` for Windows
- `cpa-policy-hub.so` for Linux
- `cpa-policy-hub.dylib` for macOS

Suggested release asset names:

- `cpa-policy-hub-windows-amd64.zip`
- `cpa-policy-hub-linux-amd64.zip`
- `cpa-policy-hub-linux-arm64.zip`
- `cpa-policy-hub-darwin-amd64.zip`
- `cpa-policy-hub-darwin-arm64.zip`

## Build commands

From this repository root:

```bash
# Windows amd64, run on Windows with a working C compiler in PATH.
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -buildmode=c-shared -o cpa-policy-hub.dll .

# Linux amd64, run on Linux or a suitable cross-compilation image.
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -o cpa-policy-hub.so .

# Linux arm64, run on Linux/arm64 or a suitable cross-compilation image.
CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=c-shared -o cpa-policy-hub.so .

# macOS builds should be produced on macOS runners.
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -buildmode=c-shared -o cpa-policy-hub.dylib .
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -o cpa-policy-hub.dylib .
```

Zip the resulting dynamic library and compute SHA-256 for each zip. Put those checksums into `registry.example.json`, then publish it as `registry.json`.

## Registry configuration in CPA

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
      storage_path: "cpa-policy-hub-state.json"
      traffic_enabled: false
      manage_config_api_keys: false
      fail_closed: false
      dry_run: true
      auth:
        exclusive: false
        keys: []
      policies: []
```

The plugin store accepts direct-install registries with `schema_version: 2`. See `registry.example.json` for the expected shape.

## Updating

To ship a new plugin version:

1. Bump `pluginVersion` in `main.go`.
2. Build all platform zips.
3. Upload zips to a new GitHub Release tag such as `v0.2.0`.
4. Update `registry.json` or `registry.example.json`:
   - `version`
   - artifact URLs
   - artifact SHA-256 values
   - optional `versions` entries if you want older versions selectable
5. CPAMC should show `update_available` when it reads the new registry.

## Why this survives official CPA updates

Official CPA updates replace CPA binaries, but the plugin artifact is installed under the CPA `plugins.dir` and is discovered at runtime. As long as the plugin ABI remains compatible and `plugins.configs.cpa-policy-hub.enabled` stays true, the plugin does not need to be manually copied again after every CPA update.

## Important notes

- Dynamic Go plugins require cgo and a C compiler for release builds.
- Avoid putting API keys or private tokens in artifact URLs. If private artifacts are needed, use `plugins.store-auth` with environment variables.
- Use versioned artifacts and checksums. Do not overwrite release assets in place.
- On Windows, updating a loaded DLL may require a CPA restart depending on whether the current file is locked.
