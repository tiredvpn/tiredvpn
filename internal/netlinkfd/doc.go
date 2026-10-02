// Package netlinkfd holds regression tests for file descriptor ownership in
// the in-tree copy of github.com/vishvananda/netlink (third_party/netlink).
// It has no runtime code; the tests live here so that `go test ./...` of the
// main module exercises the replaced dependency.
package netlinkfd
