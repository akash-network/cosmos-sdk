package keeper

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePaginationKey(t *testing.T) {
	tests := []struct {
		name        string
		key         []byte
		wantPrefix  []byte
		wantPKey    []byte
		wantErr     bool
		errContains string
	}{
		{
			name:       "nil key",
			key:        nil,
			wantPrefix: nil,
			wantPKey:   nil,
			wantErr:    false,
		},
		{
			name:       "empty key",
			key:        []byte{},
			wantPrefix: nil,
			wantPKey:   nil,
			wantErr:    false,
		},
		{
			name:        "key too short (less than 5 bytes)",
			key:         []byte{1, 2, 3},
			wantErr:     true,
			errContains: "invalid key length",
		},
		{
			name:        "invalid checksum",
			key:         []byte{0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x61, 0x62, 0x63},
			wantErr:     true,
			errContains: "invalid checksum",
		},
		{
			name:       "valid key with prefix and pKey",
			key:        encodePaginationKey([]byte("prefix"), []byte("key")),
			wantPrefix: []byte("prefix"),
			wantPKey:   []byte("key"),
			wantErr:    false,
		},
		{
			name:       "valid key with only prefix",
			key:        encodePaginationKey([]byte("prefix"), nil),
			wantPrefix: []byte("prefix"),
			wantPKey:   []byte{},
			wantErr:    false,
		},
		{
			name:       "valid key with only pKey",
			key:        encodePaginationKey(nil, []byte("key")),
			wantPrefix: []byte{},
			wantPKey:   []byte("key"),
			wantErr:    false,
		},
		{
			name:       "valid key with empty prefix and pKey",
			key:        encodePaginationKey([]byte{}, []byte{}),
			wantPrefix: []byte{},
			wantPKey:   []byte{},
			wantErr:    false,
		},
		{
			name:        "invalid key type",
			key:         func() []byte {
				// Manually construct a key with invalid type (3 instead of 1 or 2)
				data := []byte{3, 3, 'a', 'b', 'c'}
				checksum := crc32.ChecksumIEEE(data)
				buf := make([]byte, 4+len(data))
				binary.BigEndian.PutUint32(buf, checksum)
				copy(buf[4:], data)
				return buf
			}(),
			wantErr:     true,
			errContains: "invalid key type",
		},
		{
			name:        "truncated key - missing length byte",
			key:         func() []byte {
				data := []byte{1} // type without length
				checksum := crc32.ChecksumIEEE(data)
				buf := make([]byte, 4+len(data))
				binary.BigEndian.PutUint32(buf, checksum)
				copy(buf[4:], data)
				return buf
			}(),
			wantErr:     true,
			errContains: "invalid key length",
		},
		{
			name:        "truncated key - declared length exceeds actual length",
			key:         func() []byte {
				data := []byte{1, 10, 'a', 'b'} // declares length 10 but only has 2 bytes
				checksum := crc32.ChecksumIEEE(data)
				buf := make([]byte, 4+len(data))
				binary.BigEndian.PutUint32(buf, checksum)
				copy(buf[4:], data)
				return buf
			}(),
			wantErr:     true,
			errContains: "invalid key length",
		},
		{
			name:       "valid key with long prefix and pKey",
			key:        encodePaginationKey([]byte("this-is-a-very-long-prefix-value"), []byte("this-is-a-very-long-key-value")),
			wantPrefix: []byte("this-is-a-very-long-prefix-value"),
			wantPKey:   []byte("this-is-a-very-long-key-value"),
			wantErr:    false,
		},
		{
			name:       "valid key with binary data",
			key:        encodePaginationKey([]byte{0x00, 0x01, 0x02, 0xFF}, []byte{0xAA, 0xBB, 0xCC}),
			wantPrefix: []byte{0x00, 0x01, 0x02, 0xFF},
			wantPKey:   []byte{0xAA, 0xBB, 0xCC},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, pKey, err := decodePaginationKey(tt.key)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantPrefix, prefix)
				require.Equal(t, tt.wantPKey, pKey)
			}
		})
	}
}

// TestEncodeDecode_RoundTrip validates the round-trip integrity of encoding and decoding pagination keys.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		prefix []byte
		key    []byte
	}{
		{
			name:   "both nil",
			prefix: nil,
			key:    nil,
		},
		{
			name:   "both empty",
			prefix: []byte{},
			key:    []byte{},
		},
		{
			name:   "with prefix and key",
			prefix: []byte("test-prefix"),
			key:    []byte("test-key"),
		},
		{
			name:   "only prefix",
			prefix: []byte("prefix"),
			key:    []byte{},
		},
		{
			name:   "only key",
			prefix: []byte{},
			key:    []byte("key"),
		},
		{
			name:   "binary data",
			prefix: []byte{0x00, 0xFF, 0x01, 0xFE},
			key:    []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:   "large data",
			prefix: make([]byte, 200),
			key:    make([]byte, 200),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodePaginationKey(tt.prefix, tt.key)
			prefix, key, err := decodePaginationKey(encoded)

			if tt.prefix == nil && tt.key == nil {
				require.Nil(t, encoded)
				require.NoError(t, err)
				require.Nil(t, prefix)
				require.Nil(t, key)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.prefix, prefix)
				require.Equal(t, tt.key, key)
			}
		})
	}
}
