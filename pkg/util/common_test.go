package util

import (
	"testing"
)

func TestObjToStrUint32(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"uint32_zero", uint32(0), "0"},
		{"uint32_small", uint32(123), "123"},
		{"uint32_max", uint32(4294967295), "4294967295"},
		{"int", int(42), "42"},
		{"int64", int64(9223372036854775807), "9223372036854775807"},
		{"string", "hello", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := objToStr(tt.input)
			if result != tt.expected {
				t.Errorf("objToStr(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
