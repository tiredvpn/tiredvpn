# Multiport UDP Implementation - Server Side

## Обзор

Серверная часть реализации CONFIG_1 (Голый UDP Multi-Port) для распределения трафика по множеству UDP портов.

## Архитектура

### Компоненты

#### 1. Protocol (`protocol.go`)
- **Packet** - базовая структура UDP пакета с заголовком (16 байт)
- **AckPacket** - selective acknowledgment с bitmap для ARQ
- **HandshakeRequest/Response** - TCP handshake протокол

**Packet Format:**
```
[Version:1][Flags:1][SessionID:2][Seq:8][PayloadLen:2][Checksum:2][Payload:variable]
```

**Flags:**
- `FlagFIN` (0x01) - Connection termination
- `FlagACK` (0x02) - Acknowledgment
- `FlagDATA` (0x04) - Data packet

#### 2. Port Allocator (`allocator.go`)
Управляет выделением портов для клиентов:
- Выделяет диапазон портов (например, 500 портов на клиента)
- Генерирует session ID (UUID)
- Создаёт shared secret для HMAC (32 байта)
- Отслеживает использование портов (bitmap)

**Пример:**
- Client 1: порты 50000-50499
- Client 2: порты 50500-50999
- и т.д.

#### 3. Reassembly (`reassembly.go`)
Управляет ARQ (Automatic Repeat Request):

**ReceiveBuffer:**
- Собирает out-of-order пакеты
- Доставляет упорядоченные данные через канал
- Генерирует selective ACK с bitmap
- Периодическая очистка старых пакетов

**SendBuffer:**
- Отслеживает отправленные пакеты
- Запускает таймеры для retransmission
- Exponential backoff (начальный RTO: 100ms)
- Max retries: 5

#### 4. Server (`server.go`)
Основная серверная логика:

**TCP Handshake:**
1. Клиент подключается по TCP
2. Отправляет `HandshakeRequest` с clientID
3. Сервер выделяет port range через allocator
4. Возвращает `HandshakeResponse` с портами и secret
5. Создаёт session

**UDP Listeners:**
- Открывает UDP сокеты на всех портах диапазона
- Каждый порт привязан к session через `sessionsByPort`
- Обрабатывает входящие пакеты в `handleUDPPacket`

**Session Management:**
- Каждая сессия имеет ReceiveBuffer и SendBuffer
- Отдельные goroutines для ACK и data handling
- Автоматическая очистка при FIN или timeout

## Использование

### Запуск тестового сервера

```bash
# Сборка
cd ~/repos/tiredvpn
CGO_ENABLED=0 go build -o bin/mptest ./cmd/mptest

# Запуск с настройками по умолчанию
./bin/mptest server

# Запуск с кастомными параметрами
./bin/mptest server \
  --port 9000 \
  --udp-base 50000 \
  --udp-count 500 \
  --max-clients 10
```

### Параметры

- `--port` - TCP порт для handshake (default: 9000)
- `--udp-base` - Начальный UDP порт (default: 50000)
- `--udp-count` - Количество портов на клиента (default: 500)
- `--max-clients` - Максимум одновременных клиентов (default: 10)

## TCP Handshake Protocol

### Request
```json
{
  "client_id": "unique_client_identifier"
}
```

### Response
```json
{
  "start_port": 50000,
  "count": 500,
  "secret": "hex_encoded_32_bytes",
  "session_id": "uuid_string"
}
```

## UDP Packet Flow

### Data Packet (Client → Server)
```
Client sends packet with seq=N on port P
  ↓
Server receives on UDP socket P
  ↓
Finds session by port mapping
  ↓
Adds to ReceiveBuffer
  ↓
Delivers ordered data through readyChan
  ↓
Generates ACK with bitmap
```

### ACK Packet (Server → Client)
```
ReceiveBuffer generates ACK
  ↓
ACK sent on first port of range
  ↓
Client processes ACK
  ↓
Removes acknowledged packets from SendBuffer
```

## Особенности реализации

### ARQ (Automatic Repeat Request)
- **Selective ACK** с bitmap (до 256 бит)
- **Exponential backoff** для retransmission
- **Duplicate detection** - игнорируем дубликаты
- **Out-of-order handling** - буферизация до 1000 пакетов

### Производительность
- **Zero-copy где возможно** - прямая работа с буферами
- **Minimal locking** - RWMutex для read-heavy операций
- **Channel-based communication** - между компонентами
- **Concurrent UDP sockets** - параллельная обработка портов

### Безопасность
- **Checksum validation** - CRC32 для целостности
- **Session isolation** - каждая сессия независима
- **Port ownership** - порты привязаны к сессиям
- **Shared secret** - для HMAC в будущем (пока не используется)

## TODO / Ограничения

### Текущие ограничения
1. **Нет relay к target** - пока только приём данных
2. **Нет client address tracking** - не можем отправить ACK обратно
3. **Session ID mapping** - сейчас по порту, нужно по SessionID в пакете
4. **Нет timeout для неактивных сессий**
5. **Нет graceful shutdown** для сессий

### Следующие шаги
1. Реализовать relay к target servers
2. Сохранять client UDP address при первом пакете
3. Исправить SessionID mapping (uint16 → string UUID)
4. Добавить session timeout (idle detection)
5. Реализовать HMAC verification с shared secret
6. Добавить метрики и мониторинг
7. Integration tests с клиентом от Dev1

## Статистика

Сервер предоставляет статистику через `Stats()`:
- Active sessions
- Total/Used ports
- Allocator stats (free ranges)

Каждый ReceiveBuffer и SendBuffer также имеют свои метрики:
- Packets received/sent
- Retransmissions
- Duplicates/Dropped
- Out-of-order packets

## Координация с Dev1

### Что готово
- [x] Protocol format (protocol.go)
- [x] TCP handshake server
- [x] Port allocator
- [x] UDP listeners (500 sокетов)
- [x] Packet reassembly (ReceiveBuffer)
- [x] ARQ sender (SendBuffer)
- [x] Basic server structure

### Что нужно от Dev1
- [ ] Client implementation
- [ ] Port selection (HMAC-based)
- [ ] Integration testing
- [ ] Client-side ARQ logic

### Тестирование
```bash
# Dev1 запускает клиент
./mptest client --server localhost:9000

# Проверяем TCP handshake
# Проверяем UDP packet flow
# Проверяем ARQ retransmission
```

## Файлы

- `protocol.go` - Packet structures и serialization
- `allocator.go` - Port range allocation
- `reassembly.go` - ARQ buffers (receive/send)
- `server.go` - Main server logic
- `cmd/mptest/main.go` - CLI entry point
- `cmd/mptest/server.go` - Server command

## Логирование

Используется `log/slog` для structured logging:
- DEBUG: детальная информация о пакетах
- INFO: lifecycle events (start/stop/handshake)
- WARN: recoverable errors (duplicate packets, buffer full)
- ERROR: critical errors (socket errors, unmarshal failures)
