package wireajn

// AJN1 decoder for /app/trustcorpus/*/federation_trace.ajn (module realmshadow; see /app/fedproto/WORKSPACE_LAYOUT.md).

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"

	"realmshadow/pkg/trustmesh"
)

type Stats struct {
	FormatVersion   int `json:"format_version"`
	RecordsTotal    int `json:"records_total"`
	RecordsValid    int `json:"records_valid"`
	RecordsRejected int `json:"records_rejected"`
	DupSeqRejects   int `json:"dup_seq_rejects"`
	TruncatedTail   int `json:"truncated_tail"`
	PayloadBytes    int `json:"payload_bytes"`
}

func Decode(path string) ([]trustmesh.Event, Stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Stats{}, err
	}
	if len(data) < 8 || string(data[:4]) != "AJN1" {
		return nil, Stats{}, errors.New("bad magic")
	}
	formatVersion := int(binary.LittleEndian.Uint32(data[4:8]))
	stats := Stats{FormatVersion: formatVersion}
	if formatVersion != 1 {
		return nil, stats, errors.New("unsupported format_version")
	}

	off := 8
	seen := make(map[uint32]struct{})
	events := make([]trustmesh.Event, 0)

	for off < len(data) {
		if off+12 > len(data) {
			stats.RecordsRejected++
			stats.TruncatedTail = 1
			break
		}
		recordSeq := binary.BigEndian.Uint32(data[off : off+4])
		flags := binary.BigEndian.Uint16(data[off+4 : off+6])
		reserved := binary.BigEndian.Uint16(data[off+6 : off+8])
		payloadLen := binary.BigEndian.Uint32(data[off+8 : off+12])
		off += 12
		stats.RecordsTotal++

		reason := ""
		if reserved != 0 {
			reason = "BAD_RESERVED"
		} else if flags != 0 {
			reason = "BAD_FLAGS"
		} else if payloadLen > 4096 {
			reason = "LEN_OVERFLOW"
		} else if _, ok := seen[recordSeq]; ok {
			reason = "DUP_SEQ"
		}
		if off+int(payloadLen)+4 > len(data) {
			stats.RecordsRejected++
			stats.TruncatedTail = 1
			break
		}
		payload := data[off : off+int(payloadLen)]
		off += int(payloadLen)
		checksum := binary.BigEndian.Uint32(data[off : off+4])
		off += 4

		if reason == "" {
			hdr := make([]byte, 12)
			binary.LittleEndian.PutUint32(hdr[0:4], recordSeq)
			binary.LittleEndian.PutUint16(hdr[4:6], flags)
			binary.LittleEndian.PutUint16(hdr[6:8], reserved)
			binary.LittleEndian.PutUint32(hdr[8:12], payloadLen)
			if crc32.ChecksumIEEE(append(hdr, payload...)) != checksum {
				reason = "BAD_CRC"
			}
		}

		seen[recordSeq] = struct{}{}
		if reason != "" {
			stats.RecordsRejected++
			continue
		}

		var ev trustmesh.Event
		if err := json.Unmarshal(payload, &ev); err != nil {
			stats.RecordsRejected++
			continue
		}
		stats.RecordsValid++
		stats.PayloadBytes += int(payloadLen)
		events = append(events, ev)
	}

	return events, stats, nil
}
