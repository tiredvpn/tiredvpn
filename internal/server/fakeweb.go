package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	stdlog "log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/tiredvpn/tiredvpn/internal/log"
)

// The fake website mimics a stock nginx install so an active prober that hits
// the port with a plain HTTP request gets the same response a real nginx would:
// exact default page, CRLF headers in nginx order, a live Date, Content-Length,
// Last-Modified, ETag and Accept-Ranges, HEAD handled without a body, and
// keep-alive. The previous version wrote an LF-delimited stub with no Date and
// no Content-Length, which any scanner could tell apart from nginx instantly.

const nginxServerHeader = "nginx/1.24.0"

// nginxIndexHTML is the byte-exact default index page from nginx 1.24/1.25.
// Keep it exact: the Content-Length and body must match a stock install.
const nginxIndexHTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

// nginx404Body is the byte-exact 404 page from nginx 1.24.
const nginx404Body = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
`

// nginxIndexModTime is a stable Last-Modified for the built-in index page, so
// the ETag and Last-Modified stay constant across restarts the way a real file
// on disk would.
var nginxIndexModTime = time.Date(2024, time.January, 30, 12, 0, 0, 0, time.UTC)

const fakeKeepAliveTimeout = 75 * time.Second // nginx default keepalive_timeout

// serveFakeWebsite answers HTTP requests on conn as if it were nginx. It serves
// files from cfg.FakeWebRoot when set, otherwise the built-in nginx default
// page. It loops to honor keep-alive until the client closes, asks to close, or
// the idle timeout fires.
func serveFakeWebsite(conn net.Conn, cfg *Config, logger *log.Logger) {
	// We offer h2 in ALPN, so we have to be able to speak it. A client that
	// agreed on h2 is waiting for a SETTINGS frame; writing "HTTP/1.1 200 OK"
	// into that connection is a protocol error the client reports instead of
	// rendering the page, and a site that advertises h2 and then does not
	// speak it is a one-request tell. Dropping h2 from NextProtos is not the
	// alternative - every donor we imitate advertises it, and on the B1 path
	// ALPN is part of the fingerprint we match.
	if negotiatedALPN(conn) == "h2" {
		serveFakeWebsiteH2(conn, cfg, logger)
		return
	}

	logger.Debug("Serving fake website")
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(fakeKeepAliveTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		// keep-alive unless the client closed it or it's HTTP/1.0 without it.
		keepAlive := !req.Close && req.ProtoMajor == 1 && req.ProtoMinor >= 1
		if c := strings.ToLower(req.Header.Get("Connection")); c == "keep-alive" {
			keepAlive = true
		}

		writeFakeResponse(conn, req.Method, req.URL.Path, cfg, keepAlive)

		if !keepAlive {
			return
		}
	}
}

// connectionStater is a connection that can report the TLS handshake it
// completed: the standard *tls.Conn, or any wrapper that forwards the call.
type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

// connUnwrapper is a wrapper that can hand back the connection underneath it.
type connUnwrapper interface {
	Unwrap() net.Conn
}

// maxConnUnwrapDepth bounds the walk in negotiatedALPN. The dispatcher stacks
// at most two bufferedConns on a *tls.Conn (dispatch byte, then the protocol
// peek); the bound is there so a wrapper that ever returns itself cannot spin.
const maxConnUnwrapDepth = 8

// negotiatedALPN reports the ALPN protocol agreed on conn, looking through the
// buffering wrappers the dispatcher puts on top of a *tls.Conn. It returns ""
// for a connection that carries no TLS state, which is the plaintext case: the
// unknown-protocol fallback on the bare socket, imap and ssh camouflage.
func negotiatedALPN(conn net.Conn) string {
	for range maxConnUnwrapDepth {
		if cs, ok := conn.(connectionStater); ok {
			return cs.ConnectionState().NegotiatedProtocol
		}
		u, ok := conn.(connUnwrapper)
		if !ok {
			return ""
		}
		if conn = u.Unwrap(); conn == nil {
			return ""
		}
	}
	return ""
}

// serveFakeWebsiteH2 answers the same fake website over HTTP/2, for clients
// that agreed on h2 in ALPN. ServeConn reads the client preface itself, so the
// caller must hand over a connection that still replays it; every caller on
// this path does, because the dispatcher replays whatever it peeked.
func serveFakeWebsiteH2(conn net.Conn, cfg *Config, logger *log.Logger) {
	logger.Debug("Serving fake website over HTTP/2")

	// The dispatcher's protocol-detection deadline has no business bounding a
	// page load; the h1 loop overrides it per request the same way, and the
	// idle timeout below is what ends a quiet connection.
	_ = conn.SetReadDeadline(time.Time{})

	srv := &http2.Server{IdleTimeout: fakeKeepAliveTimeout}
	srv.ServeConn(conn, &http2.ServeConnOpts{
		Handler: fakeWebHandler(cfg),
		// A malformed frame from a prober is not our operator's business, and
		// the default sink is the process's standard logger.
		BaseConfig: &http.Server{ErrorLog: stdlog.New(io.Discard, "", 0)},
	})
}

// fakeWebHandler serves the same content resolveFakeContent hands the HTTP/1.1
// path, with the same headers. Ordering is not reproduced because HPACK has no
// order to reproduce; the header set is what a client can compare.
func fakeWebHandler(cfg *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Server", nginxServerHeader)

		body, contentType, modTime, ok := resolveFakeContent(r.URL.Path, cfg)
		if !ok {
			notFound := []byte(nginx404Body)
			h.Set("Content-Type", "text/html")
			h.Set("Content-Length", strconv.Itoa(len(notFound)))
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(notFound)
			return
		}

		h.Set("Content-Type", contentType)
		h.Set("Content-Length", strconv.Itoa(len(body)))
		h.Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
		h.Set("ETag", fmt.Sprintf("\"%x-%x\"", modTime.Unix(), len(body)))
		h.Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		// net/http drops the body for HEAD on its own and keeps the
		// Content-Length we declared, which is what nginx does.
		_, _ = w.Write(body)
	})
}

// writeFakeResponse builds and writes one nginx-style response for the given
// method and path. HEAD gets the same headers as GET but no body.
func writeFakeResponse(conn net.Conn, method, path string, cfg *Config, keepAlive bool) {
	body, contentType, modTime, ok := resolveFakeContent(path, cfg)
	if !ok {
		writeNginx404(conn, method, keepAlive)
		return
	}

	connHdr := "keep-alive"
	if !keepAlive {
		connHdr = "close"
	}
	etag := fmt.Sprintf("\"%x-%x\"", modTime.Unix(), len(body))

	// Header order matches nginx for a static 200.
	var h strings.Builder
	h.WriteString("HTTP/1.1 200 OK\r\n")
	h.WriteString("Server: " + nginxServerHeader + "\r\n")
	h.WriteString("Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n")
	h.WriteString("Content-Type: " + contentType + "\r\n")
	fmt.Fprintf(&h, "Content-Length: %d\r\n", len(body))
	h.WriteString("Last-Modified: " + modTime.UTC().Format(http.TimeFormat) + "\r\n")
	h.WriteString("Connection: " + connHdr + "\r\n")
	h.WriteString("ETag: " + etag + "\r\n")
	h.WriteString("Accept-Ranges: bytes\r\n")
	h.WriteString("\r\n")

	conn.Write([]byte(h.String()))
	if method != http.MethodHead {
		conn.Write(body)
	}
}

// resolveFakeContent returns the body, content type and mod time for path. It
// serves cfg.FakeWebRoot when configured (with directory-traversal protection
// and index.html for directories), otherwise the built-in nginx page for "/".
func resolveFakeContent(path string, cfg *Config) (body []byte, contentType string, modTime time.Time, ok bool) {
	// Serve from fake-root only if it actually exists as a directory. The
	// default flag value (./www) often doesn't exist, in which case we behave
	// like a freshly installed nginx and serve the built-in welcome page.
	if cfg != nil && cfg.FakeWebRoot != "" {
		if root, err := filepath.Abs(cfg.FakeWebRoot); err == nil {
			if ri, e := os.Stat(root); e == nil && ri.IsDir() {
				clean := filepath.Join(root, filepath.Clean("/"+path))
				if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
					if fi, statErr := os.Stat(clean); statErr == nil {
						if fi.IsDir() {
							idx := filepath.Join(clean, "index.html")
							if fi2, e2 := os.Stat(idx); e2 == nil && !fi2.IsDir() {
								clean, fi = idx, fi2
							}
						}
						if !fi.IsDir() {
							if data, rErr := os.ReadFile(clean); rErr == nil {
								ct := mime.TypeByExtension(filepath.Ext(clean))
								if ct == "" {
									ct = "text/html"
								}
								return data, ct, fi.ModTime(), true
							}
						}
					}
				}
				// fake-root exists but the file isn't there: welcome page for the
				// root, a real nginx 404 for anything else.
				if path == "/" || path == "/index.html" || path == "" {
					return []byte(nginxIndexHTML), "text/html", nginxIndexModTime, true
				}
				return nil, "", time.Time{}, false
			}
		}
		// fake-root configured but missing / not a directory: fall through.
	}

	// Built-in nginx welcome for the root, 404 for anything else.
	if path == "/" || path == "/index.html" || path == "" {
		return []byte(nginxIndexHTML), "text/html", nginxIndexModTime, true
	}
	return nil, "", time.Time{}, false
}

// writeNginx404 writes the exact nginx 404 page.
func writeNginx404(conn net.Conn, method string, keepAlive bool) {
	connHdr := "keep-alive"
	if !keepAlive {
		connHdr = "close"
	}
	body := []byte(nginx404Body)
	var h strings.Builder
	h.WriteString("HTTP/1.1 404 Not Found\r\n")
	h.WriteString("Server: " + nginxServerHeader + "\r\n")
	h.WriteString("Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n")
	h.WriteString("Content-Type: text/html\r\n")
	fmt.Fprintf(&h, "Content-Length: %d\r\n", len(body))
	h.WriteString("Connection: " + connHdr + "\r\n")
	h.WriteString("\r\n")

	conn.Write([]byte(h.String()))
	if method != http.MethodHead {
		conn.Write(body)
	}
}
