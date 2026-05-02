package toml

// DefaultClient returns a ClientConfig populated with sensible defaults.
// These defaults align with the legacy CLI flag defaults declared in cmd/tiredvpn.
// They alone are NOT guaranteed to pass Validate (e.g. server.address is empty);
// the caller is expected to layer TOML and/or CLI overrides on top before validating.
func DefaultClient() *ClientConfig {
	return &ClientConfig{
		Server: ClientServer{
			Address: "",
			Port:    443,
		},
		Strategy: Strategy{
			Mode: "",
		},
		TLS: ClientTLS{
			ALPN: []string{"h2", "http/1.1"},
		},
		Logging: Logging{
			Level:  "info",
			Format: "text",
			Output: "stderr",
		},
	}
}

// DefaultServer returns a ServerConfig populated with sensible defaults.
func DefaultServer() *ServerConfig {
	return &ServerConfig{
		Listen: ServerListen{
			Address: "0.0.0.0",
			Port:    443,
		},
		Strategy: Strategy{
			Mode: "",
		},
		TLS: ServerTLS{
			ALPN: []string{"h2", "http/1.1"},
		},
		Auth: ServerAuth{
			Mode: "token",
		},
		Logging: Logging{
			Level:  "info",
			Format: "text",
			Output: "stderr",
		},
	}
}
