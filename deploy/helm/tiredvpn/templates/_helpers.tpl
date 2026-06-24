{{/*
Expand the name of the chart.
*/}}
{{- define "tiredvpn.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "tiredvpn.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "tiredvpn.server.fullname" -}}
{{- printf "%s-server" (include "tiredvpn.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tiredvpn.client.fullname" -}}
{{- printf "%s-client" (include "tiredvpn.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tiredvpn.client.socks.fullname" -}}
{{- printf "%s-client-socks" (include "tiredvpn.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tiredvpn.client.tun.fullname" -}}
{{- printf "%s-client-tun" (include "tiredvpn.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart label string.
*/}}
{{- define "tiredvpn.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Base labels (applied to every resource).
*/}}
{{- define "tiredvpn.labels" -}}
helm.sh/chart: {{ include "tiredvpn.chart" . }}
{{ include "tiredvpn.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "tiredvpn.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tiredvpn.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Server-specific labels. */}}
{{- define "tiredvpn.server.labels" -}}
{{ include "tiredvpn.labels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "tiredvpn.server.selectorLabels" -}}
{{ include "tiredvpn.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end -}}

{{/* Client labels. */}}
{{- define "tiredvpn.client.socks.labels" -}}
{{ include "tiredvpn.labels" . }}
app.kubernetes.io/component: client-socks
{{- end -}}

{{- define "tiredvpn.client.socks.selectorLabels" -}}
{{ include "tiredvpn.selectorLabels" . }}
app.kubernetes.io/component: client-socks
{{- end -}}

{{- define "tiredvpn.client.tun.labels" -}}
{{ include "tiredvpn.labels" . }}
app.kubernetes.io/component: client-tun
{{- end -}}

{{- define "tiredvpn.client.tun.selectorLabels" -}}
{{ include "tiredvpn.selectorLabels" . }}
app.kubernetes.io/component: client-tun
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "tiredvpn.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tiredvpn.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference (with optional override via a workload-specific image).
*/}}
{{- define "tiredvpn.image" -}}
{{- $repo := .Values.global.image.repository -}}
{{- $tag := default .Chart.AppVersion .Values.global.image.tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}

{{- define "tiredvpn.client.tun.image" -}}
{{- $img := .Values.client.tun.image -}}
{{- if $img.repository -}}
{{- $tag := default (default .Chart.AppVersion .Values.global.image.tag) $img.tag -}}
{{- printf "%s:%s" $img.repository $tag -}}
{{- else -}}
{{- include "tiredvpn.image" . -}}
{{- end -}}
{{- end -}}

{{- define "tiredvpn.client.tun.imagePullPolicy" -}}
{{- default .Values.global.image.pullPolicy .Values.client.tun.image.pullPolicy -}}
{{- end -}}

{{- define "tiredvpn.server.tun.image" -}}
{{- $img := .Values.server.tun.image -}}
{{- $repo := default .Values.global.image.repository $img.repository -}}
{{- $tag := default (default .Chart.AppVersion .Values.global.image.tag) $img.tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}

{{- define "tiredvpn.server.tun.imagePullPolicy" -}}
{{- default .Values.global.image.pullPolicy .Values.server.tun.image.pullPolicy -}}
{{- end -}}

{{/*
ImagePullSecrets list (rendered into the pod spec).
*/}}
{{- define "tiredvpn.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Name of the server's TLS Secret.
*/}}
{{- define "tiredvpn.server.tlsSecretName" -}}
{{- if .Values.server.tls.existingSecret -}}
{{- .Values.server.tls.existingSecret -}}
{{- else -}}
{{- printf "%s-tls" (include "tiredvpn.server.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the server's auth Secret (when mode=secret or mode=tokens).
*/}}
{{- define "tiredvpn.server.authSecretName" -}}
{{- if .Values.server.auth.existingSecret -}}
{{- .Values.server.auth.existingSecret -}}
{{- else -}}
{{- printf "%s-auth" (include "tiredvpn.server.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Key inside the auth Secret.
*/}}
{{- define "tiredvpn.server.authSecretKey" -}}
{{- default "secret" .Values.server.auth.existingSecretKey -}}
{{- end -}}

{{/*
Name of the Secret holding the upstream secret.
*/}}
{{- define "tiredvpn.server.upstreamSecretName" -}}
{{- if .Values.server.config.upstream.existingSecret -}}
{{- .Values.server.config.upstream.existingSecret -}}
{{- else -}}
{{- printf "%s-upstream" (include "tiredvpn.server.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the client credentials Secret (server addr + secret).
*/}}
{{- define "tiredvpn.client.secretName" -}}
{{- if .Values.client.server.existingSecret -}}
{{- .Values.client.server.existingSecret -}}
{{- else -}}
{{- printf "%s-credentials" (include "tiredvpn.client.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "tiredvpn.client.secretAddressKey" -}}
{{- default "address" .Values.client.server.existingSecretAddressKey -}}
{{- end -}}

{{- define "tiredvpn.client.secretSecretKey" -}}
{{- default "secret" .Values.client.server.existingSecretSecretKey -}}
{{- end -}}

{{/*
Effective Redis address for the server.
If server.redis.addr is set — used as-is.
Otherwise, if the bitnami/redis subchart is enabled — {release}-redis-master:6379.
Otherwise empty (single-client mode).
*/}}
{{- define "tiredvpn.server.redisAddr" -}}
{{- if .Values.server.redis.addr -}}
{{- .Values.server.redis.addr -}}
{{- else if .Values.redis.enabled -}}
{{- printf "%s-redis-master:6379" .Release.Name -}}
{{- end -}}
{{- end -}}

{{/*
Pre-render invariant checks.
*/}}
{{- define "tiredvpn.validate" -}}
{{- if and .Values.server.enabled .Values.server.tomlConfig .Values.server.config -}}
{{/* TOML and config are de-facto mutually exclusive, but we don't fail — TOML simply overrides. */}}
{{- end -}}
{{- if and .Values.server.enabled (eq .Values.server.auth.mode "secret") (not .Values.server.tomlConfig) -}}
{{- if and (not .Values.server.auth.secret) (not .Values.server.auth.existingSecret) -}}
{{- fail "server.auth.mode=secret requires either server.auth.secret or server.auth.existingSecret" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.server.enabled .Values.server.tls.create -}}
{{- if or (not .Values.server.tls.cert) (not .Values.server.tls.key) -}}
{{- fail "server.tls.create=true requires both server.tls.cert and server.tls.key" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.server.enabled (not .Values.server.tls.create) (not .Values.server.tls.existingSecret) (not .Values.server.tomlConfig) -}}
{{- fail "server requires TLS: set server.tls.existingSecret OR server.tls.create=true with cert/key" -}}
{{- end -}}
{{- if .Values.client.enabled -}}
{{- if not (has .Values.client.mode (list "socks" "tun" "both")) -}}
{{- fail (printf "client.mode must be one of: socks, tun, both (got %q)" .Values.client.mode) -}}
{{- end -}}
{{- if and (not .Values.client.tomlConfig) (not .Values.client.server.existingSecret) -}}
{{- if or (not .Values.client.server.address) (not .Values.client.server.secret) -}}
{{- fail "client requires server address & secret: set client.server.{address,secret} OR client.server.existingSecret OR client.tomlConfig" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Helper: shouldRenderClientSocks.
*/}}
{{- define "tiredvpn.client.socks.enabled" -}}
{{- if and .Values.client.enabled (or (eq .Values.client.mode "socks") (eq .Values.client.mode "both")) -}}
true
{{- end -}}
{{- end -}}

{{- define "tiredvpn.client.tun.enabled" -}}
{{- if and .Values.client.enabled (or (eq .Values.client.mode "tun") (eq .Values.client.mode "both")) -}}
true
{{- end -}}
{{- end -}}

{{/*
=================== ARGS RENDER ===================
Render CLI args for server and client from values.*.config.
If tomlConfig is set, use -config /etc/tiredvpn/{server,client}.toml instead.
*/}}

{{- define "tiredvpn.server.args" -}}
- "server"
{{- if .Values.server.tomlConfig }}
- "-config"
- "/etc/tiredvpn/server.toml"
{{- else }}
{{- $c := .Values.server.config }}
{{- with $c.listen }}
- "-listen"
- {{ . | quote }}
{{- end }}
{{- if $c.ipv6.enabled }}
{{- with $c.listenV6 }}
- "-listen-v6"
- {{ . | quote }}
{{- end }}
{{- if $c.ipv6.dualStack }}
- "-dual-stack"
{{- end }}
{{- else }}
- "-enable-v6=false"
{{- end }}
{{- if not $c.quic.enabled }}
- "-no-quic"
{{- end }}
{{- with $c.quic.listen }}
- "-quic-listen"
- {{ . | quote }}
{{- end }}
{{- if $c.quic.sniReassembly }}
- "-quic-sni-reassembly"
{{- end }}
- "-cert"
- "/etc/tiredvpn/tls/tls.crt"
- "-key"
- "/etc/tiredvpn/tls/tls.key"
{{- if eq .Values.server.auth.mode "secret" }}
- "-secret"
- "$(TIREDVPN_SECRET)"
{{- end }}
{{- $redisAddr := include "tiredvpn.server.redisAddr" . }}
{{- if $redisAddr }}
- "-redis"
- {{ $redisAddr | quote }}
{{- end }}
{{- if $c.api.enabled }}
- "-api-addr"
- {{ $c.api.listen | quote }}
{{- end }}
{{- if $c.upstream.addr }}
- "-upstream"
- {{ $c.upstream.addr | quote }}
- "-upstream-secret"
- "$(TIREDVPN_UPSTREAM_SECRET)"
{{- end }}
{{- if $c.portHopping.enabled }}
{{- with $c.portHopping.range }}
- "-port-range"
- {{ . | quote }}
{{- end }}
- "-port-range-max"
- {{ $c.portHopping.maxPorts | quote }}
- "-port-hop-interval"
- {{ $c.portHopping.interval | quote }}
- "-port-hop-strategy"
- {{ $c.portHopping.strategy | quote }}
{{- with $c.portHopping.seed }}
- "-port-hop-seed"
- {{ . | quote }}
{{- end }}
{{- end }}
{{- with $c.tun.ip }}
- "-tun-ip"
- {{ . | quote }}
{{- end }}
{{- with $c.tun.name }}
- "-tun-name"
- {{ . | quote }}
{{- end }}
{{- with $c.tun.ipPool }}
- "-ip-pool"
- {{ . | quote }}
- "-ip-pool-lease"
- {{ $c.tun.ipPoolLease | quote }}
{{- end }}
{{- with $c.fakeRoot.path }}
- "-fake-root"
- {{ . | quote }}
{{- end }}
{{- if $c.pprof.enabled }}
- "-pprof"
- {{ $c.pprof.listen | quote }}
{{- end }}
{{- if $c.debug }}
- "-debug"
{{- end }}
{{- end }}
{{- range .Values.server.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end -}}

{{- define "tiredvpn.client.socks.args" -}}
{{- include "tiredvpn.client.args" (dict "root" . "mode" "socks") -}}
{{- end -}}

{{- define "tiredvpn.client.tun.args" -}}
{{- include "tiredvpn.client.args" (dict "root" . "mode" "tun") -}}
{{- end -}}

{{- define "tiredvpn.client.args" -}}
{{- $root := .root }}
{{- $mode := .mode }}
- "client"
{{- if $root.Values.client.tomlConfig }}
- "-config"
- "/etc/tiredvpn/client.toml"
{{- else }}
{{- $c := $root.Values.client.config }}
- "-server"
- "$(TIREDVPN_SERVER)"
- "-secret"
- "$(TIREDVPN_SECRET)"
{{- if eq $mode "socks" }}
- "-listen"
- {{ $root.Values.client.socks.listen | quote }}
{{- with $root.Values.client.socks.httpListen }}
- "-http-listen"
- {{ . | quote }}
{{- end }}
{{- else if eq $mode "tun" }}
- "-tun"
- "-tun-name"
- {{ $root.Values.client.tun.name | quote }}
- "-tun-ip"
- {{ $root.Values.client.tun.ip | quote }}
- "-tun-peer-ip"
- {{ $root.Values.client.tun.peerIp | quote }}
- "-tun-mtu"
- {{ $root.Values.client.tun.mtu | quote }}
{{- with $root.Values.client.tun.routes }}
- "-tun-routes"
- {{ . | quote }}
{{- end }}
{{- end }}
{{- with $c.strategy }}
- "-strategy"
- {{ . | quote }}
{{- end }}
{{- with $c.cover }}
- "-cover"
- {{ . | quote }}
{{- end }}
{{- if not $c.fallback }}
- "-fallback=false"
{{- end }}
{{- if $c.quic.enabled }}
- "-quic"
{{- if gt (int $c.quic.port) 0 }}
- "-quic-port"
- {{ $c.quic.port | quote }}
{{- end }}
{{- if $c.quic.sniFrag }}
- "-quic-sni-frag"
{{- end }}
{{- end }}
{{- if $c.ech.enabled }}
- "-ech"
{{- with $c.ech.config }}
- "-ech-config"
- {{ . | quote }}
{{- end }}
{{- with $c.ech.publicName }}
- "-ech-public-name"
- {{ . | quote }}
{{- end }}
{{- end }}
{{- if $c.pq.enabled }}
- "-pq"
{{- with $c.pq.serverKey }}
- "-pq-server-key"
- {{ . | quote }}
{{- end }}
{{- end }}
{{- if $c.rttMasking.enabled }}
- "-rtt-masking"
{{- with $c.rttMasking.profile }}
- "-rtt-profile"
- {{ . | quote }}
{{- end }}
{{- end }}
{{- with $c.ipv6.serverV6 }}
- "-server-v6"
- {{ . | quote }}
{{- end }}
{{- if not $c.ipv6.preferV6 }}
- "-prefer-ipv6=false"
{{- end }}
{{- if not $c.ipv6.fallbackV4 }}
- "-fallback-v4=false"
{{- end }}
{{- if $c.portHop.enabled }}
- "-port-hop"
- "-port-hop-start"
- {{ $c.portHop.start | quote }}
- "-port-hop-end"
- {{ $c.portHop.end | quote }}
- "-port-hop-interval"
- {{ $c.portHop.interval | quote }}
- "-port-hop-strategy"
- {{ $c.portHop.strategy | quote }}
{{- with $c.portHop.seed }}
- "-port-hop-seed"
- {{ . | quote }}
{{- end }}
{{- end }}
{{- with $c.adaptive.reprobeInterval }}
- "-reprobe-interval"
- {{ . | quote }}
{{- end }}
{{- if gt (int $c.adaptive.circuitThreshold) 0 }}
- "-circuit-threshold"
- {{ $c.adaptive.circuitThreshold | quote }}
{{- end }}
{{- with $c.adaptive.circuitReset }}
- "-circuit-reset"
- {{ . | quote }}
{{- end }}
{{- if $c.api.enabled }}
- "-api-addr"
- {{ $c.api.listen | quote }}
{{- end }}
{{- if $c.pprof.enabled }}
- "-pprof"
- {{ $c.pprof.listen | quote }}
{{- end }}
{{- if $c.debug }}
- "-debug"
{{- end }}
{{- end }}
{{- range $root.Values.client.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end -}}
