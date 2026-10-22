//go:build !android

package tun

// linkFallbackProbes is empty off Android: the public resolvers sit inside
// the tunnel's own routes there, so an answer from them would say nothing
// about the local link (see localLinkUp).
var linkFallbackProbes []string
