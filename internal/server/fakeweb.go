package server

import (
	"bufio"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
