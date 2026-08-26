package frames

import (
	"bytes"
	"testing"
)

func TestRoundTripAllFrames(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{"Padding", &Padding{Length: 4}},
		{"Ping", &Ping{}},
		{"ACK simple", &ACK{LargestAcked: 100, ACKDelay: 5, FirstACKRange: 10}},
		{"ACK with ECN", &ACK{LargestAcked: 100, ACKDelay: 5, FirstACKRange: 10, HasECN: true, ECT0Count: 5, ECT1Count: 3, ECNCECount: 1}},
		{"ACK with ranges", &ACK{LargestAcked: 200, ACKDelay: 3, FirstACKRange: 5, ACKRanges: []ACKRange{{Gap: 2, ACKRangeLen: 8}, {Gap: 1, ACKRangeLen: 3}}, HasECN: true, ECT0Count: 10}},
		{"ResetStream", &ResetStream{StreamID: 4, ErrorCode: 1, FinalSize: 100}},
		{"StopSending", &StopSending{StreamID: 8, ErrorCode: 2}},
		{"Crypto", &Crypto{Offset: 0, Data: []byte("hello handshake")}},
		{"NewToken", &NewToken{Token: []byte("token-data")}},
		{"Stream with offset+fin", &Stream{StreamID: 0, Offset: 100, Data: []byte("hello"), Fin: true}},
		{"Stream no offset no fin", &Stream{StreamID: 2, Offset: 0, Data: []byte("world"), Fin: false}},
		{"MaxData", &MaxData{MaximumData: 1048576}},
		{"MaxStreamData", &MaxStreamData{StreamID: 0, MaximumData: 65536}},
		{"MaxStreamsBidi", &MaxStreams{MaxStreams: 100, Unidirectional: false}},
		{"MaxStreamsUni", &MaxStreams{MaxStreams: 50, Unidirectional: true}},
		{"DataBlocked", &DataBlocked{MaximumData: 65536}},
		{"StreamDataBlocked", &StreamDataBlocked{StreamID: 0, MaximumData: 32768}},
		{"StreamsBlockedBidi", &StreamsBlocked{MaximumStreams: 100, Unidirectional: false}},
		{"StreamsBlockedUni", &StreamsBlocked{MaximumStreams: 50, Unidirectional: true}},
		{"NewConnectionID", &NewConnectionID{SequenceNumber: 1, RetirePriorTo: 0, ConnectionID: []byte{0x01, 0x02, 0x03, 0x04}, StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}},
		{"RetireConnectionID", &RetireConnectionID{SequenceNumber: 5}},
		{"PathChallenge", &PathChallenge{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		{"PathResponse", &PathResponse{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		{"ConnectionClose transport", &ConnectionClose{ErrorCode: 0x0a, TriggerFrameType: 0x06, ReasonPhrase: "bad crypto frame", ApplicationError: false}},
		{"ConnectionClose app", &ConnectionClose{ErrorCode: 42, ReasonPhrase: "app error", ApplicationError: true}},
		{"HandshakeDone", &HandshakeDone{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.frame.Encode()
			if err != nil {
				t.Fatalf("Encode error: %v", err)
			}
			decoded, n, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode error: %v", err)
			}
			if n != len(encoded) {
				t.Errorf("consumed %d bytes, want %d", n, len(encoded))
			}
			// Re-encode and compare
			reencoded, err := decoded.(Frame).Encode()
			if err != nil {
				t.Fatalf("Re-encode error: %v", err)
			}
			if !bytes.Equal(encoded, reencoded) {
				t.Errorf("round trip mismatch:\n  original: % x\n  reencoded:% x", encoded, reencoded)
			}
			// Check frame type matches
			if decoded.(Frame).FrameType() != tt.frame.FrameType() {
				t.Errorf("frame type = 0x%x, want 0x%x",
					decoded.(Frame).FrameType(), tt.frame.FrameType())
			}
		})
	}
}

func TestDecodeMultipleFrames(t *testing.T) {
	// Encode PING + PADDING + HANDSHAKE_DONE
	ping, _ := (&Ping{}).Encode()
	padding, _ := (&Padding{Length: 3}).Encode()
	hd, _ := (&HandshakeDone{}).Encode()

	data := append(append(ping, padding...), hd...)

	offset := 0
	frames := []Frame{}
	for offset < len(data) {
		f, n, err := Decode(data[offset:])
		if err != nil {
			t.Fatalf("Decode at offset %d: %v", offset, err)
		}
		frames = append(frames, f.(Frame))
		offset += n
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(frames))
	}
	if _, ok := frames[0].(*Ping); !ok {
		t.Errorf("frame 0: expected PING, got %T", frames[0])
	}
	if _, ok := frames[1].(*Padding); !ok {
		t.Errorf("frame 1: expected PADDING, got %T", frames[1])
	}
	if _, ok := frames[2].(*HandshakeDone); !ok {
		t.Errorf("frame 2: expected HANDSHAKE_DONE, got %T", frames[2])
	}
}
