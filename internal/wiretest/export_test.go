package wiretest

import "time"

// RecordAt is Record with the chunk's time given, for tests that need exact
// gaps rather than whatever a sleep overshoots to on a loaded machine.
func (d *Dump) RecordAt(dir Direction, at time.Time, b []byte) {
	if len(b) == 0 {
		return
	}
	cp := append([]byte(nil), b...)
	d.mu.Lock()
	d.segs = append(d.segs, Segment{Dir: dir, At: at, Data: cp})
	d.mu.Unlock()
}
