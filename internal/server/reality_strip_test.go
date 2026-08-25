package server

import (
	"encoding/binary"
	"testing"
)

// A genuine padding ClientHello must survive the strip-and-forward path.
//
// This is what makes -reality-cover-domain a usable workaround on a server that
// has not been updated: with a cover domain set, an unauthenticated hello is
// stripped of its padding extension and proxied to the donor, so the prober
// gets a real ServerHello instead of a bare FIN. If the strip mangled the
// hello, the donor would reject it and the distinguisher would still be there.
//
// Note the sizes on the way out: every input collapses to the same 117 bytes,
// because the padding was nearly all of it. The prober cannot see that - it is
// on our egress to the donor, not on the prober's link - but it is worth
// knowing before anyone treats the workaround as invisible.
func TestStripSurvivesGenuinePadding(t *testing.T) {
	for _, size := range []int{256, 300, 384, 450, 511, 512} {
		hello := helloWithPadding(t, "www.microsoft.com", size)

		out, err := RemoveREALITYExtension(hello)
		if err != nil {
			t.Fatalf("%d-byte hello: strip failed: %v", size, err)
		}
		if out[0] != 0x16 {
			t.Fatalf("%d-byte hello: result is not a handshake record", size)
		}
		recLen := int(binary.BigEndian.Uint16(out[3:5]))
		if recLen != len(out)-5 {
			t.Fatalf("%d-byte hello: record length %d does not match %d bytes", size, recLen, len(out)-5)
		}
		hs := out[5:]
		hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if hsLen != len(hs)-4 {
			t.Fatalf("%d-byte hello: handshake length %d does not match %d bytes", size, hsLen, len(hs)-4)
		}
		if DetectREALITYExtension(out) {
			t.Fatalf("%d-byte hello: padding extension still present after strip", size)
		}
		if _, err := ExtractSNI(out); err != nil {
			t.Fatalf("%d-byte hello: SNI lost by the strip: %v", size, err)
		}
		t.Logf("%d -> %d bytes, padding removed, SNI intact", size, len(out))
	}
}
