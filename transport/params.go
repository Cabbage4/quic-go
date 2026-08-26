// Package transport implements QUIC transport parameter encoding and decoding (RFC 9000, Section 18).
//
// Transport parameters are encoded as a sequence of (ID, length, value) tuples.
// IDs use variable-length integer encoding.
package transport

import (
	"errors"
	"fmt"
	"net"

	"github.com/Cabbage4/quic-go/varint"
)

// ParameterID represents a QUIC transport parameter ID.
type ParameterID uint64

// Transport parameter IDs (RFC 9000, Section 18.2).
const (
	ParamOriginalDestinationConnectionID    ParameterID = 0x00
	ParamMaxIdleTimeout                      ParameterID = 0x01
	ParamStatelessResetToken                ParameterID = 0x02
	ParamMaxUDPPayloadSize                  ParameterID = 0x03
	ParamInitialMaxData                     ParameterID = 0x04
	ParamInitialMaxStreamDataBidiLocal      ParameterID = 0x05
	ParamInitialMaxStreamDataBidiRemote     ParameterID = 0x06
	ParamInitialMaxStreamDataUni            ParameterID = 0x07
	ParamInitialMaxStreamsBidi              ParameterID = 0x08
	ParamInitialMaxStreamsUni               ParameterID = 0x09
	ParamAckDelayExponent                   ParameterID = 0x0a
	ParamMaxAckDelay                        ParameterID = 0x0b
	ParamDisableActiveMigration             ParameterID = 0x0c
	ParamPreferredAddress                   ParameterID = 0x0d
	ParamActiveConnectionIDLimit            ParameterID = 0x0e
	ParamInitialSourceConnectionID          ParameterID = 0x0f
	ParamRetrySourceConnectionID            ParameterID = 0x10
)

// PreferredAddress represents the server's preferred address (RFC 9000, Section 18.2).
type PreferredAddress struct {
	IPv4Addr           net.IP
	IPv4Port           uint16
	IPv6Addr           net.IP
	IPv6Port           uint16
	ConnectionID       []byte
	StatelessResetToken [16]byte
}

// Params holds QUIC transport parameters.
type Params struct {
	OriginalDestConnID        []byte
	MaxIdleTimeout            uint64 // milliseconds, 0 = disabled
	StatelessResetToken       [16]byte
	HasStatelessResetToken    bool
	MaxUDPPayloadSize         uint64 // default 65527
	InitialMaxData             uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi          uint64
	InitialMaxStreamsUni           uint64
	AckDelayExponent          uint64 // default 3
	MaxAckDelay               uint64 // default 25ms
	DisableActiveMigration    bool
	PreferredAddress          *PreferredAddress
	ActiveConnectionIDLimit   uint64 // default 2, minimum 2
	InitialSourceConnID       []byte
	RetrySourceConnID         []byte
}

// Default returns a Params struct with default values.
func Default() *Params {
	return &Params{
		MaxUDPPayloadSize:       65527,
		AckDelayExponent:        3,
		MaxAckDelay:             25,
		ActiveConnectionIDLimit: 2,
	}
}

// Encode serializes transport parameters into a byte slice (RFC 9000, Section 18).
func (p *Params) Encode() ([]byte, error) {
	buf := []byte{}
	var err error

	encode := func(id ParameterID, value []byte) error {
		buf, err = varint.Append(buf, uint64(id))
		if err != nil {
			return err
		}
		buf, err = varint.Append(buf, uint64(len(value)))
		if err != nil {
			return err
		}
		buf = append(buf, value...)
		return nil
	}

	encodeVarint := func(id ParameterID, v uint64) error {
		b, e := varint.Encode(v)
		if e != nil {
			return e
		}
		return encode(id, b)
	}

	if p.OriginalDestConnID != nil {
		if err := encode(ParamOriginalDestinationConnectionID, p.OriginalDestConnID); err != nil {
			return nil, err
		}
	}
	if p.MaxIdleTimeout > 0 {
		if err := encodeVarint(ParamMaxIdleTimeout, p.MaxIdleTimeout); err != nil {
			return nil, err
		}
	}
	if p.HasStatelessResetToken {
		if err := encode(ParamStatelessResetToken, p.StatelessResetToken[:]); err != nil {
			return nil, err
		}
	}
	if p.MaxUDPPayloadSize != 0 && p.MaxUDPPayloadSize != 65527 {
		if err := encodeVarint(ParamMaxUDPPayloadSize, p.MaxUDPPayloadSize); err != nil {
			return nil, err
		}
	}
	if p.InitialMaxData > 0 {
		if err := encodeVarint(ParamInitialMaxData, p.InitialMaxData); err != nil {
			return nil, err
		}
	}
	if p.InitialMaxStreamDataBidiLocal > 0 {
		if err := encodeVarint(ParamInitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiLocal); err != nil {
			return nil, err
		}
	}
	if p.InitialMaxStreamDataBidiRemote > 0 {
		if err := encodeVarint(ParamInitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataBidiRemote); err != nil {
			return nil, err
		}
	}
	if p.InitialMaxStreamDataUni > 0 {
		if err := encodeVarint(ParamInitialMaxStreamDataUni, p.InitialMaxStreamDataUni); err != nil {
			return nil, err
		}
	}
	if p.InitialMaxStreamsBidi > 0 {
		if err := encodeVarint(ParamInitialMaxStreamsBidi, p.InitialMaxStreamsBidi); err != nil {
			return nil, err
		}
	}
	if p.InitialMaxStreamsUni > 0 {
		if err := encodeVarint(ParamInitialMaxStreamsUni, p.InitialMaxStreamsUni); err != nil {
			return nil, err
		}
	}
	if p.AckDelayExponent != 0 && p.AckDelayExponent != 3 {
		if err := encodeVarint(ParamAckDelayExponent, p.AckDelayExponent); err != nil {
			return nil, err
		}
	}
	if p.MaxAckDelay != 0 && p.MaxAckDelay != 25 {
		if err := encodeVarint(ParamMaxAckDelay, p.MaxAckDelay); err != nil {
			return nil, err
		}
	}
	if p.DisableActiveMigration {
		if err := encode(ParamDisableActiveMigration, []byte{}); err != nil {
			return nil, err
		}
	}
	if p.PreferredAddress != nil {
		pa := p.PreferredAddress
		buf2 := make([]byte, 0, 4+2+16+2+1+len(pa.ConnectionID)+16)
		buf2 = append(buf2, pa.IPv4Addr.To4()...)
		port4 := make([]byte, 2)
		port4[0] = byte(pa.IPv4Port >> 8)
		port4[1] = byte(pa.IPv4Port)
		buf2 = append(buf2, port4...)
		buf2 = append(buf2, pa.IPv6Addr.To16()...)
		port6 := make([]byte, 2)
		port6[0] = byte(pa.IPv6Port >> 8)
		port6[1] = byte(pa.IPv6Port)
		buf2 = append(buf2, port6...)
		buf2 = append(buf2, byte(len(pa.ConnectionID)))
		buf2 = append(buf2, pa.ConnectionID...)
		buf2 = append(buf2, pa.StatelessResetToken[:]...)
		if err := encode(ParamPreferredAddress, buf2); err != nil {
			return nil, err
		}
	}
	if p.ActiveConnectionIDLimit != 0 && p.ActiveConnectionIDLimit != 2 {
		if err := encodeVarint(ParamActiveConnectionIDLimit, p.ActiveConnectionIDLimit); err != nil {
			return nil, err
		}
	}
	if p.InitialSourceConnID != nil {
		if err := encode(ParamInitialSourceConnectionID, p.InitialSourceConnID); err != nil {
			return nil, err
		}
	}
	if p.RetrySourceConnID != nil {
		if err := encode(ParamRetrySourceConnectionID, p.RetrySourceConnID); err != nil {
			return nil, err
		}
	}

	return buf, nil
}

// Decode parses transport parameters from a byte slice.
func Decode(data []byte) (*Params, error) {
	p := Default()
	offset := 0

	for offset < len(data) {
		// Read parameter ID
		id, n, err := varint.Decode(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("transport: decode param ID: %w", err)
		}
		offset += n

		// Read parameter length
		length, n, err := varint.Decode(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("transport: decode param length: %w", err)
		}
		offset += n

		if offset+int(length) > len(data) {
			return nil, errors.New("transport: parameter value too short")
		}
		value := data[offset : offset+int(length)]
		offset += int(length)

		switch ParameterID(id) {
		case ParamOriginalDestinationConnectionID:
			p.OriginalDestConnID = make([]byte, len(value))
			copy(p.OriginalDestConnID, value)
		case ParamMaxIdleTimeout:
			v, _, _ := varint.Decode(value)
			p.MaxIdleTimeout = v
		case ParamStatelessResetToken:
			copy(p.StatelessResetToken[:], value)
			p.HasStatelessResetToken = true
		case ParamMaxUDPPayloadSize:
			v, _, _ := varint.Decode(value)
			p.MaxUDPPayloadSize = v
		case ParamInitialMaxData:
			v, _, _ := varint.Decode(value)
			p.InitialMaxData = v
		case ParamInitialMaxStreamDataBidiLocal:
			v, _, _ := varint.Decode(value)
			p.InitialMaxStreamDataBidiLocal = v
		case ParamInitialMaxStreamDataBidiRemote:
			v, _, _ := varint.Decode(value)
			p.InitialMaxStreamDataBidiRemote = v
		case ParamInitialMaxStreamDataUni:
			v, _, _ := varint.Decode(value)
			p.InitialMaxStreamDataUni = v
		case ParamInitialMaxStreamsBidi:
			v, _, _ := varint.Decode(value)
			p.InitialMaxStreamsBidi = v
		case ParamInitialMaxStreamsUni:
			v, _, _ := varint.Decode(value)
			p.InitialMaxStreamsUni = v
		case ParamAckDelayExponent:
			v, _, _ := varint.Decode(value)
			p.AckDelayExponent = v
		case ParamMaxAckDelay:
			v, _, _ := varint.Decode(value)
			p.MaxAckDelay = v
		case ParamDisableActiveMigration:
			p.DisableActiveMigration = true
		case ParamActiveConnectionIDLimit:
			v, _, _ := varint.Decode(value)
			p.ActiveConnectionIDLimit = v
		case ParamInitialSourceConnectionID:
			p.InitialSourceConnID = make([]byte, len(value))
			copy(p.InitialSourceConnID, value)
		case ParamRetrySourceConnectionID:
			p.RetrySourceConnID = make([]byte, len(value))
			copy(p.RetrySourceConnID, value)
		default:
			// Unknown parameters MUST be ignored (RFC 9000, Section 18.1)
		}
	}

	return p, nil
}
