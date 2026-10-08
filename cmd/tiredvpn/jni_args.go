package main

import (
	"fmt"
	"strconv"

	"github.com/tiredvpn/tiredvpn/internal/client"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// This file has no build tag on purpose. parseClientArgs is the JNI argv
// parser and only jni_android.go calls it, but jni_android.go needs
// GOOS=android with cgo, so neither the regular CI nor `go test` on a Linux
// box ever compiled the parser. Living here, it builds and is tested
// everywhere; jni_android.go keeps only the glue.

// parseClientArgs parses command line args into client.Config
func parseClientArgs(args []string) (_ *client.Config, err error) {
	// Errors go to the app's log and its error state as is; hide any -secret
	// value that came back inside one (argv_redact.go).
	defer func() { err = redactArgError(err, args) }()

	cfg := &client.Config{
		AndroidMode: true,
		// TUN is opt-in via -tun. The app's TUN path always passes -tun; proxy mode
		// passes -listen instead and must NOT be forced into TUN (it has no tun-fd,
		// so a forced TUN setup fails and proxy mode never starts).
		TunMode: false,
		// 1500 left no room for tunnel encapsulation (4-byte length frame + the
		// strategy's TLS/WebSocket/etc. overhead), so inner TCP segments clamped
		// to MTU-40 produced outer packets larger than the underlying path MTU.
		// On Android that meant fragmentation / PMTUD blackholes and badly
		// degraded download throughput (issue #27). 1280 (the IPv6 minimum, same
		// as tun.DefaultMTU) leaves a safe margin for all encapsulation. The app
		// can still override via -tun-mtu.
		TunMTU: 1280,
		// The desktop client and the server default -reality-require-data-v2 to
		// true (main.go), but this literal bypasses the flag set, so the field
		// would otherwise stay at its zero value (false) and leave Android as the
		// only platform silently accepting the malleable v1 REALITY data layer.
		// Match the other clients: require the authenticated v2 layer.
		REALITYRequireDataV2: true,
	}

	// -config is applied BEFORE the scan below, so that the args the app passed
	// explicitly overwrite what the file said. This parser has no equivalent of
	// flag.Visit - "was it set?" is only knowable by whether the token is
	// present - so the precedence has to come from the order of the two passes.
	if path := scanArgValue(args, "-config"); path != "" {
		if err := applyClientTOMLConfig(cfg, path, nil); err != nil {
			return nil, err
		}
	}

	// Shaper preset/seed are captured during the scan and applied after the loop
	// so a -shaper-seed in any position still feeds the same -shaper build.
	var (
		shaperName    string
		shaperSeed    int64
		sawServerFlag bool
	)

	// Tokens echoed into a log come from this copy, never from args: an
	// unknown "--secret" or "-secret=v" is echoed whole, and so is the value
	// token after it.
	logArgs := redactArgs(args)

	// Parse flags from args (simple parser, doesn't use flag package)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-config":
			// Consumed before the loop; skip its value so it is not reported
			// as an unknown token.
			if i+1 < len(args) {
				i++
			}
		case "-server":
			if i+1 < len(args) {
				cfg.ServerAddr = args[i+1]
				// A single address on the command line collapses a
				// [[servers]] list from -config, the same way the desktop
				// flag does. Without it -server would look accepted and the
				// client would dial the list instead.
				sawServerFlag = true
				i++
			}
		case "-secret":
			if i+1 < len(args) {
				cfg.Secret = args[i+1]
				i++
			}
		// Proxy mode: SOCKS5/HTTP listener (no -tun). Without this the app's
		// proxy connection mode silently lost its listen address.
		case "-listen":
			if i+1 < len(args) {
				cfg.ListenAddr = args[i+1]
				i++
			}
		case "-http-listen":
			if i+1 < len(args) {
				cfg.HTTPListenAddr = args[i+1]
				i++
			}
		case "-tun-ip":
			if i+1 < len(args) {
				cfg.TunIP = args[i+1]
				i++
			}
		case "-tun-peer-ip":
			if i+1 < len(args) {
				cfg.TunPeerIP = args[i+1]
				i++
			}
		case "-tun-mtu":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &cfg.TunMTU)
				i++
			}
		case "-control-socket":
			if i+1 < len(args) {
				cfg.ControlSocket = args[i+1]
				i++
			}
		case "-protect-path":
			if i+1 < len(args) {
				cfg.ProtectPath = args[i+1]
				i++
			}
		// The protect channel protocol the app speaks. Apps up to 1.11.0 do not
		// send it and speak protocol 1; an older core ignores it as an unknown
		// flag, so a newer app must keep serving protocol 1 as well.
		case "-protect-proto":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err != nil {
					log.Warn("parseClientArgs: invalid -protect-proto value %q: %v", logArgs[i+1], strconvReason(err))
				} else if v == 1 || v == 2 {
					cfg.ProtectProto = v
				} else {
					log.Warn("parseClientArgs: unsupported -protect-proto value %q, using protocol 1", logArgs[i+1])
				}
				i++
			}
		case "-strategy":
			if i+1 < len(args) {
				cfg.StrategyName = args[i+1]
				i++
			}
		case "-gost-tls13-pin":
			if i+1 < len(args) {
				cfg.GOSTTLSPin = args[i+1]
				i++
			}
		case "-gost-tls13-port":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.GOSTTLSPort = v
				} else {
					log.Warn("parseClientArgs: invalid -gost-tls13-port value %q: %v", logArgs[i+1], strconvReason(err))
				}
				i++
			}
		// -cover is the canonical flag (matches CLI -cover and what the app sends).
		// -cover-host is kept as a legacy alias.
		case "-cover", "-cover-host":
			if i+1 < len(args) {
				cfg.CoverHost = args[i+1]
				i++
			}
		case "-debug":
			cfg.Debug = true
		case "-tun":
			cfg.TunMode = true
		case "-android":
			cfg.AndroidMode = true

		// QUIC transport
		case "-quic":
			cfg.QUICEnabled = true
		case "-quic-port":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.QUICPort = v
				} else {
					log.Warn("parseClientArgs: invalid -quic-port value %q: %v", logArgs[i+1], strconvReason(err))
				}
				i++
			}
		case "-quic-sni-frag":
			cfg.QUICSNIFragEnabled = true

		// RTT masking
		case "-rtt-masking":
			cfg.RTTMaskingEnabled = true
		case "-rtt-profile":
			if i+1 < len(args) {
				cfg.RTTProfile = args[i+1]
				i++
			}

		// Mid-session fallback
		case "-fallback":
			cfg.EnableFallback = true

		// Traffic shaper (built identically to CLI runClient via applyShaperFlag)
		case "-shaper":
			if i+1 < len(args) {
				shaperName = args[i+1]
				i++
			}
		case "-shaper-seed":
			if i+1 < len(args) {
				if v, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					shaperSeed = v
				} else {
					log.Warn("parseClientArgs: invalid -shaper-seed value %q: %v", logArgs[i+1], strconvReason(err))
				}
				i++
			}

		case "-tls-fingerprint":
			if i+1 < len(args) {
				cfg.TLSFingerprint = args[i+1]
				i++
			}

		// ECH (Encrypted Client Hello)
		case "-ech":
			cfg.ECHEnabled = true
		case "-ech-config":
			if i+1 < len(args) {
				cfg.ECHConfigB64 = args[i+1]
				i++
			}
		case "-ech-public-name":
			if i+1 < len(args) {
				cfg.ECHPublicName = args[i+1]
				i++
			}

		// IPv6 inside the tunnel (dual-stack)
		case "-tun-ipv6":
			if i+1 < len(args) {
				cfg.TunIPv6Policy = args[i+1]
				i++
			}

		// IPv6 transport
		case "-server-v6":
			if i+1 < len(args) {
				cfg.ServerAddrV6 = args[i+1]
				sawServerFlag = true
				i++
			}
		case "-prefer-ipv6":
			if i+1 < len(args) {
				if v, err := strconv.ParseBool(args[i+1]); err == nil {
					cfg.PreferIPv6 = v
				} else {
					log.Warn("parseClientArgs: invalid -prefer-ipv6 value %q: %v", logArgs[i+1], strconvReason(err))
				}
				i++
			}
		case "-fallback-v4":
			if i+1 < len(args) {
				if v, err := strconv.ParseBool(args[i+1]); err == nil {
					cfg.FallbackToV4 = v
				} else {
					log.Warn("parseClientArgs: invalid -fallback-v4 value %q: %v", logArgs[i+1], strconvReason(err))
				}
				i++
			}

		default:
			// No more silent drops: log every unrecognized token so flag
			// contract drift between the app and the core is visible.
			log.Warn("parseClientArgs: ignoring unknown flag %q", logArgs[i])
		}
	}

	if sawServerFlag {
		cfg.Servers = collapseServers(cfg.Servers, cfg.ServerAddr, cfg.ServerAddrV6)
	}

	// Build the shaper exactly like the CLI path (runClient -> applyShaperFlag):
	// presets.ByName(name, seed) for cfg.Shaper and presets.IDForName(name) for
	// cfg.ShaperID, including the unknown-preset error.
	if shaperName != "" {
		if err := applyShaperFlag(cfg, shaperName, shaperSeed); err != nil {
			return nil, err
		}
	}

	// Validate required fields
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("missing required flag: -server")
	}

	return cfg, nil
}
