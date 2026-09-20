package strategy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"strconv"
)

// The five carriers, as protocols rather than as prefixes.
//
// v1 wrote a plausible-looking opening and then appended raw bytes behind it: a
// DNS query with trailing data the message never declared, a GET with a body and
// no Content-Length, an SSH KEXINIT with every algorithm name-list empty, an
// EHLO followed by binary, and gRPC framed over HTTP/1.1 with a length field of
// zero in front of a non-empty message. Each of those is a parse error to the
// protocol being imitated, which makes the imitation worth less than nothing:
// a middlebox that parses at all sees a malformed instance of a common protocol,
// and that is rarer than the protocol itself.
//
// Here each variant carries our bytes in a place the real protocol already has
// for opaque data - an EDNS0 local-use option, an HTTP entity body with a
// matching Content-Length, an SSH string inside a correctly padded binary
// packet, a SASL initial response, a gRPC-Web message - so the packet parses.
//
// What this does NOT claim: that the resulting length distributions match
// anything measured. They are not checked against a capture of real DNS, HTTP,
// SSH, SMTP or gRPC-Web, because we have no such capture. Recorded explicitly,
// per rule 3.

var (
	// ErrConfusionNeedMore means the input looks like a carrier but stops
	// short. The caller should read more bytes and try again.
	ErrConfusionNeedMore = errors.New("confusion: carrier truncated")

	// ErrConfusionNotCarrier means the input is not one of our carriers. The
	// caller must treat the peer as an unknown one.
	ErrConfusionNotCarrier = errors.New("confusion: not a confusion carrier")
)

// Variant identifiers. They are the low bytes of ConfusionType and are mixed
// into every derivation, so a marker minted for one carrier is rejected in
// another.
const (
	confusionVariantDNS  = byte(ConfusionDNSoverTLS)
	confusionVariantHTTP = byte(ConfusionHTTPoverTLS)
	confusionVariantSSH  = byte(ConfusionSSHoverTLS)
	confusionVariantSMTP = byte(ConfusionSMTPoverTLS)
	confusionVariantGRPC = byte(ConfusionMultiLayer)
)

// confusionMaxCarrier bounds how many bytes a peer may spend on a first packet
// before we give up on it. A carrier holds a nonce, a marker and one sealed
// frame; 32 KiB is far above anything a well-behaved client produces and keeps
// a peer from making the server buffer without limit.
const confusionMaxCarrier = 32 * 1024

// ConfusionSSHBanner is the identification string the SSH carrier opens with.
//
// It is exported because the dispatcher needs it: the SSH camouflage transport
// opens with a banner too, and the banner is the only thing either of them has
// put on the wire when the dispatcher has to choose. The two differ by their
// claimed OpenSSH release, and both strings are ones real hosts send.
const ConfusionSSHBanner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"

// confusionUserAgents and confusionGRPCPaths are drawn per connection so the
// carrier is not one fixed string. Discrete pools, like the real populations
// they stand in for; no claim is made that the mix matches a measured one.
var confusionUserAgents = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
}

var confusionGRPCPaths = []string{
	"/google.firestore.v1.Firestore/Listen",
	"/google.pubsub.v1.Subscriber/StreamingPull",
	"/grpc.health.v1.Health/Watch",
}

// ConfusionCarrier is a parsed first packet, in either direction.
type ConfusionCarrier struct {
	// Variant is which of the five shapes carried it.
	Variant byte

	// Nonce is the per-connection nonce, present on requests only.
	Nonce []byte

	// Body is everything the carrier was carrying for us: on a request the
	// marker followed by sealed frames, on a response the server's marker
	// followed by sealed frames. The nonce has already been stripped.
	Body []byte

	// Length is how many bytes of the input the carrier occupied, so the
	// caller knows where the sealed stream continues.
	Length int

	// Domain and Echo are what a response has to mirror to stay plausible:
	// the name the request used, and for DNS the transaction id plus the
	// question section verbatim.
	Domain string
	Echo   []byte
}

// BuildConfusionRequest wraps nonce+marker+sealed in the carrier for variant.
func BuildConfusionRequest(variant byte, nonce, marker, sealed []byte) ([]byte, error) {
	body := make([]byte, 0, len(nonce)+len(marker)+len(sealed))
	body = append(body, nonce...)
	body = append(body, marker...)
	body = append(body, sealed...)

	domain := getRandomConfusionDomain()
	switch variant {
	case confusionVariantDNS:
		return buildDNSCarrier(domain, 0x0100, 1, body)
	case confusionVariantHTTP:
		return buildHTTPRequestCarrier(domain, body), nil
	case confusionVariantSSH:
		return buildSSHCarrier(confSSHMsgKexECDHInit, body)
	case confusionVariantSMTP:
		return buildSMTPRequestCarrier(domain, body), nil
	case confusionVariantGRPC:
		return buildGRPCRequestCarrier(domain, body), nil
	default:
		return nil, fmt.Errorf("confusion: unknown variant %d", variant)
	}
}

// BuildConfusionResponse wraps marker+sealed in the answering shape of the
// carrier the request arrived in.
func BuildConfusionResponse(req *ConfusionCarrier, marker, sealed []byte) ([]byte, error) {
	body := make([]byte, 0, len(marker)+len(sealed))
	body = append(body, marker...)
	body = append(body, sealed...)

	switch req.Variant {
	case confusionVariantDNS:
		return buildDNSResponseCarrier(req, body)
	case confusionVariantHTTP:
		return buildHTTPResponseCarrier(body), nil
	case confusionVariantSSH:
		return buildSSHCarrier(confSSHMsgKexECDHReply, body)
	case confusionVariantSMTP:
		return buildSMTPResponseCarrier(req.Domain, body), nil
	case confusionVariantGRPC:
		return buildGRPCResponseCarrier(body), nil
	default:
		return nil, fmt.Errorf("confusion: unknown variant %d", req.Variant)
	}
}

// ParseConfusionRequest classifies data as one of the five carriers and returns
// the bytes it was carrying. It never looks at a secret: authentication happens
// on the body, by the caller.
func ParseConfusionRequest(data []byte) (*ConfusionCarrier, error) {
	if len(data) == 0 {
		return nil, ErrConfusionNeedMore
	}

	switch {
	case hasPrefixUpTo(data, []byte(ConfusionSSHBanner)):
		return parseSSHCarrier(data, confSSHMsgKexECDHInit, confusionVariantSSH)
	case hasPrefixUpTo(data, []byte("EHLO ")):
		return parseSMTPRequestCarrier(data)
	case hasPrefixUpTo(data, []byte("POST ")):
		return parseHTTPCarrier(data, true)
	default:
		return parseDNSCarrier(data, 0x0100)
	}
}

// ParseConfusionResponse decodes the answering carrier for a known variant.
func ParseConfusionResponse(variant byte, data []byte) (*ConfusionCarrier, error) {
	switch variant {
	case confusionVariantDNS:
		return parseDNSCarrier(data, 0x8180)
	case confusionVariantHTTP, confusionVariantGRPC:
		c, err := parseHTTPCarrier(data, false)
		if err != nil {
			return nil, err
		}
		if c.Variant != variant {
			return nil, ErrConfusionNotCarrier
		}
		return c, nil
	case confusionVariantSSH:
		return parseSSHCarrier(data, confSSHMsgKexECDHReply, confusionVariantSSH)
	case confusionVariantSMTP:
		return parseSMTPResponseCarrier(data)
	default:
		return nil, ErrConfusionNotCarrier
	}
}

// hasPrefixUpTo reports whether data starts with prefix, treating a data shorter
// than prefix but matching as far as it goes as a match - the caller will ask
// for more bytes.
func hasPrefixUpTo(data, prefix []byte) bool {
	if len(data) >= len(prefix) {
		return bytes.HasPrefix(data, prefix)
	}
	return bytes.HasPrefix(prefix, data)
}

// splitCarrierNonce peels the nonce off a request body.
func splitCarrierNonce(c *ConfusionCarrier) (*ConfusionCarrier, error) {
	if len(c.Body) < ConfusionNonceLen+confusionMarkerMinLen {
		return nil, ErrConfusionNotCarrier
	}
	c.Nonce = c.Body[:ConfusionNonceLen]
	c.Body = c.Body[ConfusionNonceLen:]
	return c, nil
}

// ---------------------------------------------------------------- DNS

// confusionEDNSOptionCode is a local/experimental EDNS0 option code (RFC 6891
// reserves 65001-65534 for local use). Opaque data in a local-use option is what
// that range exists for, unlike RFC 7830 padding, whose contents are specified
// to be zero.
const confusionEDNSOptionCode = 65001

// confusionDNSMinMessage is the smallest message our builder can produce:
// 12-byte header, a question, an OPT record, and a body of at least a nonce
// and the shortest marker. Anything smaller is not ours, and saying so from
// the first two bytes keeps random traffic from being asked for more.
const confusionDNSMinMessage = 12 + 2 + 4 + 11 + 4 + ConfusionNonceLen + confusionMarkerMinLen

// buildDNSCarrier emits a DNS-over-TCP message: header, one question, and one
// OPT pseudo-record in the additional section carrying body in a local-use
// option.
func buildDNSCarrier(domain string, flags uint16, qr int, body []byte) ([]byte, error) {
	if len(body)+4 > 0xffff {
		return nil, errors.New("confusion: dns carrier body too large")
	}

	var msg bytes.Buffer
	txid := make([]byte, 2)
	if _, err := rand.Read(txid); err != nil {
		return nil, err
	}
	msg.Write(txid)
	binary.Write(&msg, binary.BigEndian, flags)
	binary.Write(&msg, binary.BigEndian, uint16(1)) // QDCOUNT
	binary.Write(&msg, binary.BigEndian, uint16(0)) // ANCOUNT
	binary.Write(&msg, binary.BigEndian, uint16(0)) // NSCOUNT
	binary.Write(&msg, binary.BigEndian, uint16(1)) // ARCOUNT (the OPT record)

	msg.Write(encodeDNSName(domain))
	msg.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE=A, QCLASS=IN

	writeDNSOptRecord(&msg, body)
	return frameDNSOverTCP(msg.Bytes())
}

// buildDNSResponseCarrier mirrors the request's transaction id and question, as
// a resolver's answer does.
func buildDNSResponseCarrier(req *ConfusionCarrier, body []byte) ([]byte, error) {
	if len(req.Echo) < 2 {
		return nil, ErrConfusionNotCarrier
	}
	if len(body)+4 > 0xffff {
		return nil, errors.New("confusion: dns carrier body too large")
	}

	var msg bytes.Buffer
	msg.Write(req.Echo[:2])                              // same transaction id
	binary.Write(&msg, binary.BigEndian, uint16(0x8180)) // response, RD, RA, NOERROR
	binary.Write(&msg, binary.BigEndian, uint16(1))
	binary.Write(&msg, binary.BigEndian, uint16(0))
	binary.Write(&msg, binary.BigEndian, uint16(0))
	binary.Write(&msg, binary.BigEndian, uint16(1))
	msg.Write(req.Echo[2:]) // question section, verbatim

	writeDNSOptRecord(&msg, body)
	return frameDNSOverTCP(msg.Bytes())
}

func writeDNSOptRecord(msg *bytes.Buffer, body []byte) {
	msg.WriteByte(0x00)                               // root name
	binary.Write(msg, binary.BigEndian, uint16(41))   // TYPE = OPT
	binary.Write(msg, binary.BigEndian, uint16(4096)) // requestor's UDP payload size
	binary.Write(msg, binary.BigEndian, uint32(0))    // ext-rcode, version 0, flags
	binary.Write(msg, binary.BigEndian, uint16(4+len(body)))
	binary.Write(msg, binary.BigEndian, uint16(confusionEDNSOptionCode))
	binary.Write(msg, binary.BigEndian, uint16(len(body)))
	msg.Write(body)
}

func frameDNSOverTCP(msg []byte) ([]byte, error) {
	if len(msg) > 0xffff {
		return nil, errors.New("confusion: dns message too large")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out, nil
}

// parseDNSCarrier validates the message strictly enough that arbitrary traffic
// whose fifth and sixth bytes happen to read 0x01 0x00 no longer qualifies - the
// defect that made the relay reachable with no marker at all.
func parseDNSCarrier(data []byte, wantFlags uint16) (*ConfusionCarrier, error) {
	if len(data) < 2 {
		return nil, ErrConfusionNeedMore
	}
	msgLen := int(binary.BigEndian.Uint16(data[:2]))
	if msgLen < confusionDNSMinMessage || msgLen > confusionMaxCarrier {
		return nil, ErrConfusionNotCarrier
	}

	// The twelve-byte header is checked as soon as it is available, before the
	// rest of the message is demanded. Otherwise any two opening bytes that
	// read as a plausible length - "GE", "PR", 0x1603 - would make the caller
	// wait for kilobytes that are never coming, which is a way to hold a
	// goroutine per connection without sending anything.
	if len(data) >= 2+12 {
		hdr := data[2 : 2+12]
		if binary.BigEndian.Uint16(hdr[2:4]) != wantFlags {
			return nil, ErrConfusionNotCarrier
		}
		if binary.BigEndian.Uint16(hdr[4:6]) != 1 || // QDCOUNT
			binary.BigEndian.Uint16(hdr[6:8]) != 0 || // ANCOUNT
			binary.BigEndian.Uint16(hdr[8:10]) != 0 || // NSCOUNT
			binary.BigEndian.Uint16(hdr[10:12]) != 1 { // ARCOUNT
			return nil, ErrConfusionNotCarrier
		}
	}
	if len(data) < 2+msgLen {
		return nil, ErrConfusionNeedMore
	}
	msg := data[2 : 2+msgLen]

	if binary.BigEndian.Uint16(msg[2:4]) != wantFlags {
		return nil, ErrConfusionNotCarrier
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 || // QDCOUNT
		binary.BigEndian.Uint16(msg[6:8]) != 0 || // ANCOUNT
		binary.BigEndian.Uint16(msg[8:10]) != 0 || // NSCOUNT
		binary.BigEndian.Uint16(msg[10:12]) != 1 { // ARCOUNT
		return nil, ErrConfusionNotCarrier
	}

	off := 12
	qStart := off
	for {
		if off >= len(msg) {
			return nil, ErrConfusionNotCarrier
		}
		l := int(msg[off])
		if l&0xc0 != 0 { // compression pointer: a query we never write
			return nil, ErrConfusionNotCarrier
		}
		off++
		if l == 0 {
			break
		}
		off += l
	}
	if off+4 > len(msg) {
		return nil, ErrConfusionNotCarrier
	}
	off += 4 // QTYPE, QCLASS
	question := msg[qStart:off]

	// OPT pseudo-record: root name, TYPE 41, then the rdata we put the body in.
	if off+11 > len(msg) {
		return nil, ErrConfusionNotCarrier
	}
	if msg[off] != 0x00 || binary.BigEndian.Uint16(msg[off+1:off+3]) != 41 {
		return nil, ErrConfusionNotCarrier
	}
	rdLen := int(binary.BigEndian.Uint16(msg[off+9 : off+11]))
	off += 11
	if off+rdLen > len(msg) || rdLen < 4 {
		return nil, ErrConfusionNotCarrier
	}
	rdata := msg[off : off+rdLen]
	if binary.BigEndian.Uint16(rdata[:2]) != confusionEDNSOptionCode {
		return nil, ErrConfusionNotCarrier
	}
	optLen := int(binary.BigEndian.Uint16(rdata[2:4]))
	if 4+optLen > len(rdata) {
		return nil, ErrConfusionNotCarrier
	}

	echo := make([]byte, 0, 2+len(question))
	echo = append(echo, msg[0:2]...)
	echo = append(echo, question...)

	c := &ConfusionCarrier{
		Variant: confusionVariantDNS,
		Body:    rdata[4 : 4+optLen],
		Length:  2 + msgLen,
		Echo:    echo,
	}
	if wantFlags == 0x0100 {
		return splitCarrierNonce(c)
	}
	return c, nil
}

// ---------------------------------------------------------------- HTTP / gRPC-Web

func buildHTTPRequestCarrier(domain string, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("POST /upload HTTP/1.1\r\n")
	fmt.Fprintf(&buf, "Host: %s\r\n", domain)
	fmt.Fprintf(&buf, "User-Agent: %s\r\n", confusionUserAgents[mathrand.Intn(len(confusionUserAgents))])
	buf.WriteString("Accept: */*\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n")
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("Connection: keep-alive\r\n")
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func buildHTTPResponseCarrier(body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 OK\r\n")
	buf.WriteString("Server: nginx\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n")
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("Connection: keep-alive\r\n")
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func buildGRPCRequestCarrier(domain string, body []byte) []byte {
	frame := buildGRPCWebFrame(body)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "POST %s HTTP/1.1\r\n", confusionGRPCPaths[mathrand.Intn(len(confusionGRPCPaths))])
	fmt.Fprintf(&buf, "Host: %s\r\n", domain)
	buf.WriteString("Content-Type: application/grpc-web+proto\r\n")
	buf.WriteString("X-Grpc-Web: 1\r\n")
	buf.WriteString("X-User-Agent: grpc-web-javascript/0.1\r\n")
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(frame))
	buf.WriteString("\r\n")
	buf.Write(frame)
	return buf.Bytes()
}

func buildGRPCResponseCarrier(body []byte) []byte {
	frame := buildGRPCWebFrame(body)

	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 OK\r\n")
	buf.WriteString("Content-Type: application/grpc-web+proto\r\n")
	buf.WriteString("Grpc-Status: 0\r\n")
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(frame))
	buf.WriteString("\r\n")
	buf.Write(frame)
	return buf.Bytes()
}

// buildGRPCWebFrame emits [flags:1][length:4] over a protobuf message whose
// field 1 is our bytes - a length-delimited field, which is what wire type 2 is.
// v1 wrote a length of zero in front of a non-empty message and called it gRPC.
func buildGRPCWebFrame(body []byte) []byte {
	msg := make([]byte, 0, len(body)+8)
	msg = append(msg, 0x0a) // field 1, wire type 2
	msg = appendProtoVarint(msg, uint64(len(body)))
	msg = append(msg, body...)

	out := make([]byte, 5, 5+len(msg))
	out[0] = 0x00 // not compressed
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	return append(out, msg...)
}

func appendProtoVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func readProtoVarint(b []byte) (uint64, int, bool) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		if shift > 63 {
			return 0, 0, false
		}
		v |= uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

// parseHTTPCarrier handles both the plain HTTP variant and the gRPC-Web one;
// the Content-Type tells them apart.
func parseHTTPCarrier(data []byte, request bool) (*ConfusionCarrier, error) {
	headEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headEnd < 0 {
		if len(data) > confusionMaxCarrier {
			return nil, ErrConfusionNotCarrier
		}
		return nil, ErrConfusionNeedMore
	}
	head := data[:headEnd]

	if request {
		if !bytes.HasPrefix(head, []byte("POST ")) {
			return nil, ErrConfusionNotCarrier
		}
	} else if !bytes.HasPrefix(head, []byte("HTTP/1.1 200 ")) {
		return nil, ErrConfusionNotCarrier
	}

	contentLen, ok := httpHeaderInt(head, "content-length")
	if !ok || contentLen < 0 || contentLen > confusionMaxCarrier {
		return nil, ErrConfusionNotCarrier
	}
	bodyStart := headEnd + 4
	if len(data) < bodyStart+contentLen {
		return nil, ErrConfusionNeedMore
	}
	body := data[bodyStart : bodyStart+contentLen]

	variant := confusionVariantHTTP
	if ct, ok := httpHeaderValue(head, "content-type"); ok && bytes.Contains(ct, []byte("grpc")) {
		variant = confusionVariantGRPC
		inner, err := parseGRPCWebFrame(body)
		if err != nil {
			return nil, err
		}
		body = inner
	}

	c := &ConfusionCarrier{
		Variant: variant,
		Body:    body,
		Length:  bodyStart + contentLen,
		Domain:  string(httpHeaderString(head, "host")),
	}
	if request {
		return splitCarrierNonce(c)
	}
	return c, nil
}

func parseGRPCWebFrame(body []byte) ([]byte, error) {
	if len(body) < 5 {
		return nil, ErrConfusionNotCarrier
	}
	if body[0] != 0x00 {
		return nil, ErrConfusionNotCarrier
	}
	msgLen := int(binary.BigEndian.Uint32(body[1:5]))
	if msgLen < 2 || 5+msgLen > len(body) {
		return nil, ErrConfusionNotCarrier
	}
	msg := body[5 : 5+msgLen]
	if msg[0] != 0x0a {
		return nil, ErrConfusionNotCarrier
	}
	fieldLen, n, ok := readProtoVarint(msg[1:])
	if !ok || 1+n+int(fieldLen) > len(msg) {
		return nil, ErrConfusionNotCarrier
	}
	return msg[1+n : 1+n+int(fieldLen)], nil
}

func httpHeaderValue(head []byte, name string) ([]byte, bool) {
	needle := append([]byte("\r\n"), []byte(name)...)
	lower := bytes.ToLower(head)
	idx := bytes.Index(lower, append(needle, ':'))
	if idx < 0 {
		return nil, false
	}
	start := idx + len(needle) + 1
	end := bytes.Index(head[start:], []byte("\r\n"))
	if end < 0 {
		end = len(head) - start
	}
	return bytes.TrimSpace(head[start : start+end]), true
}

func httpHeaderString(head []byte, name string) []byte {
	v, _ := httpHeaderValue(head, name)
	return v
}

func httpHeaderInt(head []byte, name string) (int, bool) {
	v, ok := httpHeaderValue(head, name)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(string(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

// ---------------------------------------------------------------- SSH

const (
	confSSHMsgKexInit      = byte(20)
	confSSHMsgKexECDHInit  = byte(30)
	confSSHMsgKexECDHReply = byte(31)
	confSSHMaxBanner       = 255
	confSSHMaxPacket       = confusionMaxCarrier
	confSSHBlockSize       = 8
	confSSHMinPadding      = 4
	confSSHPacketHeader    = 5 // uint32 packet_length + uint8 padding_length
)

// Real OpenSSH 8.9 name-lists. v1 sent ten empty ones, which no implementation
// ever does and which a parser that reads KEXINIT at all would notice.
var confSSHKexNameLists = []string{
	"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c",
	"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
	"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com",
	"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com",
	"none,zlib@openssh.com",
	"none,zlib@openssh.com",
	"",
	"",
}

// buildSSHCarrier emits a banner, a realistic KEXINIT, and a second binary
// packet whose payload is msgType followed by our body as an SSH string.
func buildSSHCarrier(msgType byte, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(ConfusionSSHBanner)
	buf.WriteString("\r\n")

	kexPayload, err := buildConfSSHKexInitPayload()
	if err != nil {
		return nil, err
	}
	kexPacket, err := wrapConfSSHPacket(kexPayload)
	if err != nil {
		return nil, err
	}
	buf.Write(kexPacket)

	payload := make([]byte, 0, 5+len(body))
	payload = append(payload, msgType)
	var strLen [4]byte
	binary.BigEndian.PutUint32(strLen[:], uint32(len(body)))
	payload = append(payload, strLen[:]...)
	payload = append(payload, body...)

	dataPacket, err := wrapConfSSHPacket(payload)
	if err != nil {
		return nil, err
	}
	buf.Write(dataPacket)
	return buf.Bytes(), nil
}

func buildConfSSHKexInitPayload() ([]byte, error) {
	var p bytes.Buffer
	p.WriteByte(confSSHMsgKexInit)

	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return nil, err
	}
	p.Write(cookie)

	for _, list := range confSSHKexNameLists {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(list)))
		p.Write(l[:])
		p.WriteString(list)
	}
	p.WriteByte(0x00)           // first_kex_packet_follows
	p.Write([]byte{0, 0, 0, 0}) // reserved
	return p.Bytes(), nil
}

// wrapConfSSHPacket frames payload per RFC 4253 section 6: the packet length
// covers the padding-length byte, the payload and the padding, and the total
// must be a multiple of the cipher block size (8 while unencrypted) with at
// least four bytes of padding.
func wrapConfSSHPacket(payload []byte) ([]byte, error) {
	base := 1 + len(payload)
	padLen := confSSHBlockSize - ((4 + base) % confSSHBlockSize)
	if padLen < confSSHMinPadding {
		padLen += confSSHBlockSize
	}
	packetLen := base + padLen
	if packetLen > confSSHMaxPacket {
		return nil, errors.New("confusion: ssh packet too large")
	}

	out := make([]byte, 4+1+len(payload)+padLen)
	binary.BigEndian.PutUint32(out[:4], uint32(packetLen))
	out[4] = byte(padLen)
	copy(out[5:], payload)
	if _, err := rand.Read(out[5+len(payload):]); err != nil {
		return nil, err
	}
	return out, nil
}

func parseSSHCarrier(data []byte, wantMsg byte, variant byte) (*ConfusionCarrier, error) {
	nl := bytes.Index(data, []byte("\r\n"))
	if nl < 0 {
		if len(data) > confSSHMaxBanner {
			return nil, ErrConfusionNotCarrier
		}
		return nil, ErrConfusionNeedMore
	}
	// The full identification string, not just the SSH-2.0 prefix. A peer that
	// opens with some other banner is somebody else's SSH client, and asking it
	// for two more packets it will never send would hold a goroutine until the
	// deadline for nothing.
	if !bytes.HasPrefix(data, []byte(ConfusionSSHBanner)) {
		return nil, ErrConfusionNotCarrier
	}
	off := nl + 2

	kexLen, err := confSSHPacketLen(data, off)
	if err != nil {
		return nil, err
	}
	off += 4 + kexLen

	dataLen, err := confSSHPacketLen(data, off)
	if err != nil {
		return nil, err
	}
	if len(data) < off+4+dataLen {
		return nil, ErrConfusionNeedMore
	}
	padLen := int(data[off+4])
	payloadLen := dataLen - 1 - padLen
	if padLen < confSSHMinPadding || payloadLen < 5 {
		return nil, ErrConfusionNotCarrier
	}
	payload := data[off+5 : off+5+payloadLen]
	if payload[0] != wantMsg {
		return nil, ErrConfusionNotCarrier
	}
	strLen := int(binary.BigEndian.Uint32(payload[1:5]))
	if 5+strLen > len(payload) {
		return nil, ErrConfusionNotCarrier
	}

	c := &ConfusionCarrier{
		Variant: variant,
		Body:    payload[5 : 5+strLen],
		Length:  off + 4 + dataLen,
	}
	if wantMsg == confSSHMsgKexECDHInit {
		return splitCarrierNonce(c)
	}
	return c, nil
}

func confSSHPacketLen(data []byte, off int) (int, error) {
	if len(data) < off+confSSHPacketHeader {
		return 0, ErrConfusionNeedMore
	}
	l := int(binary.BigEndian.Uint32(data[off : off+4]))
	if l < confSSHPacketHeader || l > confSSHMaxPacket {
		return 0, ErrConfusionNotCarrier
	}
	if len(data) < off+4+l {
		return 0, ErrConfusionNeedMore
	}
	return l, nil
}

// ---------------------------------------------------------------- SMTP

// The SMTP carrier keeps one known deviation from the real protocol: the client
// speaks first, while a real SMTP client waits for the server's 220 greeting.
// Fixing it would mean the server greeting every connection before it knows who
// is calling, which is exactly the one-packet identification this whole change
// removes. The deviation is recorded rather than papered over.
func buildSMTPRequestCarrier(domain string, body []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "EHLO %s\r\n", domain)
	fmt.Fprintf(&buf, "AUTH PLAIN %s\r\n", base64.StdEncoding.EncodeToString(body))
	return buf.Bytes()
}

func buildSMTPResponseCarrier(domain string, body []byte) []byte {
	if domain == "" {
		domain = getRandomConfusionDomain()
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "220 mail.%s ESMTP Postfix\r\n", domain)
	fmt.Fprintf(&buf, "250-mail.%s\r\n", domain)
	buf.WriteString("250-PIPELINING\r\n")
	buf.WriteString("250-SIZE 10240000\r\n")
	buf.WriteString("250 AUTH PLAIN LOGIN\r\n")
	fmt.Fprintf(&buf, "334 %s\r\n", base64.StdEncoding.EncodeToString(body))
	return buf.Bytes()
}

func parseSMTPRequestCarrier(data []byte) (*ConfusionCarrier, error) {
	ehloEnd := bytes.Index(data, []byte("\r\n"))
	if ehloEnd < 0 {
		if len(data) > 512 {
			return nil, ErrConfusionNotCarrier
		}
		return nil, ErrConfusionNeedMore
	}
	if !bytes.HasPrefix(data, []byte("EHLO ")) {
		return nil, ErrConfusionNotCarrier
	}
	domain := string(bytes.TrimSpace(data[5:ehloEnd]))

	rest := data[ehloEnd+2:]
	const authPrefix = "AUTH PLAIN "
	// The command name is checked before the line terminator is demanded: the
	// 1.10.0 carrier put raw bytes here with no CRLF at all, and waiting for
	// one would have been a wait with no end.
	if !hasPrefixUpTo(rest, []byte(authPrefix)) {
		return nil, ErrConfusionNotCarrier
	}
	authEnd := bytes.Index(rest, []byte("\r\n"))
	if authEnd < 0 {
		if len(rest) > confusionMaxCarrier {
			return nil, ErrConfusionNotCarrier
		}
		return nil, ErrConfusionNeedMore
	}
	if !bytes.HasPrefix(rest, []byte(authPrefix)) {
		return nil, ErrConfusionNotCarrier
	}
	body, err := base64.StdEncoding.DecodeString(string(rest[len(authPrefix):authEnd]))
	if err != nil {
		return nil, ErrConfusionNotCarrier
	}

	return splitCarrierNonce(&ConfusionCarrier{
		Variant: confusionVariantSMTP,
		Body:    body,
		Length:  ehloEnd + 2 + authEnd + 2,
		Domain:  domain,
	})
}

func parseSMTPResponseCarrier(data []byte) (*ConfusionCarrier, error) {
	if !hasPrefixUpTo(data, []byte("220 ")) {
		return nil, ErrConfusionNotCarrier
	}
	off := 0
	for {
		end := bytes.Index(data[off:], []byte("\r\n"))
		if end < 0 {
			if len(data) > confusionMaxCarrier {
				return nil, ErrConfusionNotCarrier
			}
			return nil, ErrConfusionNeedMore
		}
		line := data[off : off+end]
		off += end + 2
		if !bytes.HasPrefix(line, []byte("334 ")) {
			continue
		}
		body, err := base64.StdEncoding.DecodeString(string(line[4:]))
		if err != nil {
			return nil, ErrConfusionNotCarrier
		}
		return &ConfusionCarrier{
			Variant: confusionVariantSMTP,
			Body:    body,
			Length:  off,
		}, nil
	}
}

// ---------------------------------------------------------------- reading

// ReadConfusionCarrier pulls bytes from r until parse succeeds, and returns the
// carrier plus whatever was read past it.
//
// pre is data the caller already holds (a dispatcher's peek). On
// ErrConfusionNotCarrier it returns everything consumed so the caller can put
// the connection back the way it found it and let another detector look.
func ReadConfusionCarrier(r io.Reader, pre []byte, parse func([]byte) (*ConfusionCarrier, error)) (*ConfusionCarrier, []byte, []byte, error) {
	buf := make([]byte, 0, 2048)
	buf = append(buf, pre...)

	for {
		if len(buf) > 0 {
			c, err := parse(buf)
			if err == nil {
				return c, buf[c.Length:], buf, nil
			}
			if !errors.Is(err, ErrConfusionNeedMore) {
				return nil, nil, buf, err
			}
		}
		if len(buf) >= confusionMaxCarrier {
			return nil, nil, buf, ErrConfusionNotCarrier
		}

		chunk := make([]byte, 2048)
		n, err := r.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			continue
		}
		if err != nil {
			return nil, nil, buf, err
		}
	}
}
