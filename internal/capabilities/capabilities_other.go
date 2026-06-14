//go:build !linux

package capabilities

func Probe() Set { return Set{} }
