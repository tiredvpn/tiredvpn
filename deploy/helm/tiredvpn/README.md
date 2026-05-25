# tiredvpn Helm chart

Production-grade Helm chart для развёртывания [tiredvpn](https://github.com/tiredvpn/tiredvpn-oss) — DPI-resistant VPN — в Kubernetes. Чарт поддерживает развёртывание сервера (exit node) и/или клиента (SOCKS5-прокси либо TUN-туннель) в одном release.

## Установка

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami    # для опционального Redis
cd deploy/helm/tiredvpn
helm dependency update
helm install my-tiredvpn . -f my-values.yaml
```

Минимальные требования: Kubernetes ≥ 1.25, Helm ≥ 3.8.

## Примеры использования

### 1. Минимальный сервер (single-client)

```bash
helm install vpn deploy/helm/tiredvpn \
  --set server.tls.create=true \
  --set-file server.tls.cert=server.crt \
  --set-file server.tls.key=server.key \
  --set server.auth.secret="$(openssl rand -hex 32)"
```

### 2. Multi-client сервер с Redis

```bash
helm install vpn deploy/helm/tiredvpn \
  --set server.tls.existingSecret=vpn-tls \
  --set server.auth.mode=external \
  --set redis.enabled=true \
  --set server.autoscaling.enabled=true \
  --set server.metrics.serviceMonitor.enabled=true
```

После старта добавь клиентов через admin API:

```bash
kubectl exec deploy/vpn-tiredvpn-server -- /tiredvpn admin add \
  -api http://127.0.0.1:8080 -server vpn.example.com:443
```

### 3. Сервер с port-hopping и IPv6 dual-stack

```bash
helm install vpn deploy/helm/tiredvpn -f - <<EOF
server:
  tls: { existingSecret: vpn-tls }
  auth: { mode: secret, secret: "$(openssl rand -hex 32)" }
  config:
    portHopping:
      enabled: true
      range: "47000-47100"
      interval: 60s
      strategy: random
    quic:
      sniReassembly: true
EOF
```

### 4. Клиент в SOCKS5-режиме (доступен из других подов кластера)

```bash
helm install proxy deploy/helm/tiredvpn -f - <<EOF
server: { enabled: false }
client:
  enabled: true
  mode: socks
  server:
    address: "vpn.example.com:443"
    secret: "<shared-secret>"
  socks:
    replicaCount: 2
    pdb: { enabled: true }
EOF
```

Из любого пода: `curl -x socks5h://proxy-tiredvpn-client-socks:1080 https://ifconfig.me`.

### 5. Клиент в TUN-режиме (DaemonSet, тоннелирует трафик узла)

> ⚠️  Дефолтный образ `tiredvpn/tiredvpn` собран `FROM scratch` и не содержит `ip`/`iptables`, которые клиент использует для конфигурации TUN. Соберите собственный образ на базе alpine/debian с `iproute2` + `iptables` и укажите его через `client.tun.image.repository`.

```bash
helm install vpn-tunnel deploy/helm/tiredvpn -f - <<EOF
server: { enabled: false }
client:
  enabled: true
  mode: tun
  server: { existingSecret: vpn-credentials }
  tun:
    routes: "0.0.0.0/0"
    usePrivileged: false   # NET_ADMIN+NET_RAW caps вместо privileged
    image:
      repository: myorg/tiredvpn-tun
      tag: 1.1.3
EOF
```

## Структура values

| Раздел | Описание |
|---|---|
| `global.image.*` | Реджистри, тег (default — `appVersion` чарта), pullPolicy |
| `serviceAccount.*` | SA создаётся один на release |
| `server.enabled` | toggle сервера |
| `server.config.*` | CLI-флаги бинаря (listen, ipv6, quic, portHopping, tun, upstream, fakeRoot, api, pprof, debug) |
| `server.tls.{existingSecret, create, cert, key}` | TLS-сертификаты: готовый Secret или inline PEM |
| `server.auth.{mode, secret, tokens, existingSecret}` | Аутентификация: `secret`/`tokens`/`external` |
| `server.redis.addr` | Внешний Redis (если не используется bitnami subchart) |
| `server.tomlConfig` | Альтернатива `config.*` — сырой TOML, монтируется как ConfigMap |
| `server.service.{main, api}` | Два отдельных Service: main (TCP+UDP/LoadBalancer) и api (ClusterIP) |
| `server.{resources, podSecurityContext, securityContext, nodeSelector, ...}` | стандартные K8s-настройки пода |
| `server.pdb.enabled` | PodDisruptionBudget |
| `server.networkPolicy.enabled` | NetworkPolicy (ingress main+api, egress DNS+world) |
| `server.metrics.serviceMonitor.enabled` | Prometheus ServiceMonitor на `/metrics` через api-порт |
| `server.autoscaling.enabled` | HPA — **требует** общий Redis backend |
| `client.enabled` | toggle клиента |
| `client.mode` | `socks` (Deployment) \| `tun` (DaemonSet) \| `both` |
| `client.server.{address, secret, existingSecret}` | Адрес+secret VPN-сервера |
| `client.config.*` | CLI-флаги: strategy, cover, quic, ech, pq, rttMasking, ipv6, portHop, adaptive, api, pprof |
| `client.tomlConfig` | Альтернатива `config.*` |
| `client.socks.*` | SOCKS-режим: listen/replicaCount/service/resources/PDB |
| `client.tun.*` | TUN-режим: name/ip/peerIp/mtu/routes/usePrivileged/image |
| `client.metrics.serviceMonitor.enabled` | Только для SOCKS-режима (тоже через `api`-порт) |
| `client.networkPolicy.enabled` | NetworkPolicy для SOCKS |
| `redis.enabled` | Поднимает bitnami/redis как зависимость; если включён и `server.redis.addr` пусто — сервер автоматически подключится к `<release>-redis-master:6379` |

Полный список значений и их default'ы смотри в [values.yaml](./values.yaml) (комментарии рядом с каждым полем).

## CLI-флаги ↔ values

Чарт рендерит args бинаря из `server.config.*` / `client.config.*` (см. `_helpers.tpl`). Если нужен флаг, не покрытый values напрямую, используй:

- `server.extraArgs` / `client.extraArgs` — добавляются в конец args (`extraArgs: ["-foo", "bar"]`);
- `server.tomlConfig` / `client.tomlConfig` — целиком заменяет CLI-флаги на TOML-конфиг (см. `configs/server.example.toml` в основном репо).

## Проверка перед установкой

```bash
helm lint deploy/helm/tiredvpn -f ci/server-minimal-values.yaml
helm template my-release deploy/helm/tiredvpn -f ci/server-minimal-values.yaml | kubectl apply --dry-run=client -f -
```

В `ci/` лежат фикстуры для типичных сценариев (server-minimal, server-redis, server-porthop, client-socks, client-tun, both) — используются для lint-чеков в CI/локально.

## Совместимость

- Версии Helm: 3.8+
- Версии Kubernetes: 1.25+ (использует `policy/v1` PDB, `autoscaling/v2` HPA, `networking.k8s.io/v1` NetworkPolicy)
- Версии tiredvpn: соответствует `appVersion` Chart.yaml (по умолчанию `1.1.3`)

## Лицензия

AGPL-3.0 (наследуется от основного проекта).
