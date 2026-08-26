// Package errors implements QUIC error codes (RFC 9000, Section 20.1).
package errors

import "fmt"

// TransportErrorCode represents a QUIC transport error code.
type TransportErrorCode uint64

// Transport error codes (RFC 9000, Section 20.1).
const (
	NoError                  TransportErrorCode = 0x00
	InternalError            TransportErrorCode = 0x01
	ConnectionRefused        TransportErrorCode = 0x02
	FlowControlError         TransportErrorCode = 0x03
	StreamLimitError         TransportErrorCode = 0x04
	StreamStateError         TransportErrorCode = 0x05
	FinalSizeError           TransportErrorCode = 0x06
	FrameEncodingError       TransportErrorCode = 0x07
	TransportParameterError  TransportErrorCode = 0x08
	ConnectionIDLimitError   TransportErrorCode = 0x09
	ProtocolViolation        TransportErrorCode = 0x0a
	InvalidToken             TransportErrorCode = 0x0b
	ApplicationError         TransportErrorCode = 0x0c
	CryptoBufferExceeded     TransportErrorCode = 0x0d
	KeyUpdateError           TransportErrorCode = 0x0e
	AEADLimitError           TransportErrorCode = 0x0f
	NoViablePath             TransportErrorCode = 0x10
)

// String returns a human-readable error code name.
func (e TransportErrorCode) String() string {
	switch e {
	case NoError:
		return "NO_ERROR"
	case InternalError:
		return "INTERNAL_ERROR"
	case ConnectionRefused:
		return "CONNECTION_REFUSED"
	case FlowControlError:
		return "FLOW_CONTROL_ERROR"
	case StreamLimitError:
		return "STREAM_LIMIT_ERROR"
	case StreamStateError:
		return "STREAM_STATE_ERROR"
	case FinalSizeError:
		return "FINAL_SIZE_ERROR"
	case FrameEncodingError:
		return "FRAME_ENCODING_ERROR"
	case TransportParameterError:
		return "TRANSPORT_PARAMETER_ERROR"
	case ConnectionIDLimitError:
		return "CONNECTION_ID_LIMIT_ERROR"
	case ProtocolViolation:
		return "PROTOCOL_VIOLATION"
	case InvalidToken:
		return "INVALID_TOKEN"
	case ApplicationError:
		return "APPLICATION_ERROR"
	case CryptoBufferExceeded:
		return "CRYPTO_BUFFER_EXCEEDED"
	case KeyUpdateError:
		return "KEY_UPDATE_ERROR"
	case AEADLimitError:
		return "AEAD_LIMIT_ERROR"
	case NoViablePath:
		return "NO_VIABLE_PATH"
	default:
		return fmt.Sprintf("UNKNOWN_ERROR(0x%x)", uint64(e))
	}
}

// Error wraps a transport error code with a message.
type Error struct {
	Code    TransportErrorCode
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("quic: %s: %s", e.Code, e.Message)
}

// New creates a new QUIC transport error.
func New(code TransportErrorCode, msg string) *Error {
	return &Error{Code: code, Message: msg}
}
