package main

const (
	pluginID                     = "cpa-policy-hub"
	legacyPluginID               = "api-key-token-limiter"
	pluginDisplayName            = "CPA Policy Hub"
	pluginVersion                = "0.1.0"
	interfaceOverrideHeader      = "X-CLIProxy-Force-Interface"
	interfaceOverrideMatchHeader = "X-CLIProxy-Force-Interface-Match"
	maxManagementBodyBytes       = 4 << 20
	maxAuthModelBodyBytes        = 1 << 20
)

var currentLimiter = &limiter{
	cfg: pluginConfig{
		StoragePath: "cpa-policy-hub-state.json",
	},
	configuredKeys:  map[string]keyRule{},
	credentialIndex: map[string]string{},
	state: persistedState{
		Keys:  map[string]keyRule{},
		Usage: map[string]*usageCounter{},
	},
	saveSignal: make(chan struct{}, 1),
	stopSignal: make(chan struct{}),
}

func init() {
	currentLimiter.mu.Lock()
	currentLimiter.refreshRuntimeSnapshotLocked()
	currentLimiter.mu.Unlock()
	currentLimiter.startStateSaver()
}
