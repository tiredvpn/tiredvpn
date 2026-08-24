package detect

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
)

// StreamID identifies one TCP flow within a capture.
type StreamID string

// ParseTSharkCSV turns tshark field output into per-stream packet lists.
//
// The expected invocation, four fields, no header:
//
//	tshark -r dump.pcap -Y tcp -T fields -E separator=, \
//	       -e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.len
//
// Direction is derived rather than asked for, because tshark has no field for
// it: the first packet seen on a stream is the client's, so its destination
// port is the server's for the rest of that stream. On a capture that starts
// mid-flow this guesses, and a capture that starts mid-flow is useless for the
// heuristic anyway - it scores the handshake.
//
// Zero-length segments are dropped here rather than downstream, so the packet
// counts that MaxFirstBurstPackets guards match what nDPI sees.
func ParseTSharkCSV(r io.Reader) (map[StreamID][]Packet, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 4
	cr.ReuseRecord = true

	out := make(map[StreamID][]Packet)
	serverPort := make(map[StreamID]string)

	for line := 1; ; line++ {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tshark csv line %d: %w", line, err)
		}

		stream, src, dst, lenField := StreamID(rec[0]), rec[1], rec[2], rec[3]
		payload, err := strconv.ParseUint(lenField, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("tshark csv line %d: tcp.len %q: %w", line, lenField, err)
		}

		if _, seen := serverPort[stream]; !seen {
			serverPort[stream] = dst
		}
		if payload == 0 {
			continue
		}
		out[stream] = append(out[stream], Packet{
			ToServer:   dst == serverPort[stream] && src != serverPort[stream],
			PayloadLen: uint32(payload),
		})
	}
	return out, nil
}

// FlowReport is the verdict for one flow.
type FlowReport struct {
	Stream    StreamID
	Worst     Window
	Margin    float64
	Caught    bool
	CaughtBy  string
	Distances map[string]float64
}

// Analyse scores every stream in a capture. subtractOverhead should be true
// for traffic carrying an inner TLS session, which is the case this heuristic
// exists for.
func Analyse(streams map[StreamID][]Packet, subtractOverhead bool) []FlowReport {
	var out []FlowReport
	for id, pkts := range streams {
		bursts := BurstsFromPackets(pkts, subtractOverhead)
		w, margin, ok := Worst(bursts)
		if !ok {
			continue
		}
		caught, by := Caught(w)
		out = append(out, FlowReport{
			Stream:    id,
			Worst:     w,
			Margin:    margin,
			Caught:    caught,
			CaughtBy:  by,
			Distances: Distances(w),
		})
	}
	return out
}
