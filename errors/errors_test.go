package errors

import "testing"

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		code TransportErrorCode
		name string
	}{
		{NoError, "NO_ERROR"},
		{InternalError, "INTERNAL_ERROR"},
		{FlowControlError, "FLOW_CONTROL_ERROR"},
		{ProtocolViolation, "PROTOCOL_VIOLATION"},
		{InvalidToken, "INVALID_TOKEN"},
		{ApplicationError, "APPLICATION_ERROR"},
		{CryptoBufferExceeded, "CRYPTO_BUFFER_EXCEEDED"},
		{KeyUpdateError, "KEY_UPDATE_ERROR"},
		{AEADLimitError, "AEAD_LIMIT_ERROR"},
		{NoViablePath, "NO_VIABLE_PATH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code.String() != tt.name {
				t.Errorf("got %s, want %s", tt.code.String(), tt.name)
			}
		})
	}
}

func TestUnknownErrorCode(t *testing.T) {
	code := TransportErrorCode(0xff)
	if got := code.String(); got != "UNKNOWN_ERROR(0xff)" {
		t.Errorf("got %s, want UNKNOWN_ERROR(0xff)", got)
	}
}

func TestNewError(t *testing.T) {
	e := New(FlowControlError, "stream limit exceeded")
	if e.Code != FlowControlError {
		t.Errorf("code = %s, want %s", e.Code, FlowControlError)
	}
	want := "quic: FLOW_CONTROL_ERROR: stream limit exceeded"
	if e.Error() != want {
		t.Errorf("error = %q, want %q", e.Error(), want)
	}
}
