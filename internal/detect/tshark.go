package detect

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
)

// StreamID identifies one TCP flow within a capture.
type StreamID string

// ParseTSharkCSV turns tshark field output into per-stream packet lists.
//
// The expected invocation, five fields, no header:
//
//	tshark -r dump.pcap -Y tcp -T fields -E separator=, \
//	       -e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.payload
//
// The payload column may be either the full hex payload or just its first byte;
// only the first byte is read, because that is all the heuristic's gate looks
// at. An empty column is fine and means an empty segment.
//
// Direction is derived rather than asked for, because tshark has no field for
// it: the first packet seen on a stream is the client's, so its destination
// port is the server's for the rest of that stream. On a capture that starts
// mid-flow this guesses, and a capture that starts mid-flow is useless for the
// heuristic anyway - it scores the handshake.
//
// Zero-length segments are kept, not dropped: the walk in Flow.Bursts needs to
// see them to match the original, which returns early on them.
func ParseTSharkCSV(r io.Reader) (map[StreamID][]Packet, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // the payload column may be absent on empty segments
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
		if len(rec) < 4 {
			return nil, fmt.Errorf("tshark csv line %d: want at least 4 fields, got %d", line, len(rec))
		}

		stream, src, dst, lenField := StreamID(rec[0]), rec[1], rec[2], rec[3]
		payloadLen, err := strconv.ParseUint(lenField, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("tshark csv line %d: tcp.len %q: %w", line, lenField, err)
		}

		var first byte
		if len(rec) >= 5 && len(rec[4]) >= 2 {
			b, err := hex.DecodeString(rec[4][:2])
			if err != nil {
				return nil, fmt.Errorf("tshark csv line %d: tcp.payload %q: %w", line, rec[4][:2], err)
			}
			first = b[0]
		}

		if _, seen := serverPort[stream]; !seen {
			serverPort[stream] = dst
		}
		out[stream] = append(out[stream], Packet{
			ToServer:   dst == serverPort[stream] && src != serverPort[stream],
			PayloadLen: uint32(payloadLen),
			FirstByte:  first,
		})
	}
	return out, nil
}

// FlowReport is the verdict for one flow.
type FlowReport struct {
	Stream StreamID
	Mode   Mode
	// Excluded means the heuristic bailed out and produced no verdict. That is
	// different from Caught == false, which means it looked and found nothing.
	Excluded  bool
	Scored    bool
	Worst     Window
	Margin    float64
	Caught    bool
	CaughtBy  string
	Distances map[string]float64
}

// Analyse scores every stream in a capture under the given mode.
//
// The mode is the caller's to supply because it is not visible in the packets:
// it follows from how nDPI classified the flow, which in practice follows from
// the port. Guessing it here would hide the very thing that decides the answer.
func Analyse(streams map[StreamID][]Packet, mode Mode) []FlowReport {
	var out []FlowReport
	for id, pkts := range streams {
		rep := FlowReport{Stream: id, Mode: mode}

		bursts, excluded := Flow{Packets: pkts, Mode: mode}.Bursts()
		if excluded {
			rep.Excluded = true
			out = append(out, rep)
			continue
		}

		w, margin, ok := Worst(bursts)
		if !ok {
			out = append(out, rep)
			continue
		}
		rep.Scored = true
		rep.Worst, rep.Margin = w, margin
		rep.Caught, rep.CaughtBy = Caught(w)
		rep.Distances = Distances(w)
		out = append(out, rep)
	}
	return out
}
