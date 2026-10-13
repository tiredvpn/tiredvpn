# REALITY single-flight candidate

Source: [TLS handshake burst measurements](https://habr.com/ru/articles/1044396/). The article reports observations, not a stable protocol specification. This candidate tests whether spacing TLS handshake starts across all donor SNI improves behavior on paths affected by closely spaced handshakes.

Select with `-strategy reality_singleflight`. The variant uses the same REALITY wire format, fingerprint, authentication, data framing, and server configuration as `reality`. It allows one handshake at a time across donor names, with 450–600 ms between starts. The original `-strategy reality` retains its per-SNI limit of two and 250–500 ms spacing. The variant has low automatic priority and is intended for explicit lab A/B checks. It can add latency when new concurrent connections are opened.

Compatibility and successful data delivery do not prove improved reliability under active filtering. Evaluate the candidate with controlled A/B runs using the same server, port, network path, and workload during a reproducible baseline failure. Record handshake timing and successful tunneled requests; reject the hypothesis if the candidate does not improve success or only adds latency.
