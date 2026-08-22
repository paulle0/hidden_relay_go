package nrvaddress

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

// A valid 32-byte key, lowercase hex.
const testPubKey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		addr Address
	}{
		{
			name: "no relays",
			addr: Address{PublicKey: testPubKey},
		},
		{
			name: "one relay",
			addr: Address{PublicKey: testPubKey, Relays: []string{"wss://relay.example.com"}},
		},
		{
			name: "several relays keep their order",
			addr: Address{PublicKey: testPubKey, Relays: []string{
				"wss://relay.example.com",
				"wss://nostr.example.org/v1",
				"ws://localhost:7777",
			}},
		},
		{
			name: "relay url with query characters",
			addr: Address{PublicKey: testPubKey, Relays: []string{"wss://relay.example.com/?a=1&b=2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.addr.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}

			bech32Addr, urlAddr, err := Encode(tt.addr)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if !strings.HasPrefix(bech32Addr, HRP+"1") {
				t.Errorf("bech32 address %q does not start with %q", bech32Addr, HRP+"1")
			}
			if !strings.HasPrefix(urlAddr, URLPrefix) {
				t.Errorf("url address %q does not start with %q", urlAddr, URLPrefix)
			}

			for _, encoded := range []string{bech32Addr, urlAddr} {
				got, err := Decode(encoded)
				if err != nil {
					t.Fatalf("Decode(%q) error = %v", encoded, err)
				}
				assertAddressEqual(t, got, tt.addr)
			}
		})
	}
}

func TestEncodeURLFormat(t *testing.T) {
	addr := Address{PublicKey: testPubKey, Relays: []string{"wss://a.example", "wss://b.example"}}

	got, err := EncodeURL(addr)
	if err != nil {
		t.Fatalf("EncodeURL() error = %v", err)
	}
	want := URLPrefix + testPubKey +
		"?relay=wss%3A%2F%2Fa.example" +
		"&relay=wss%3A%2F%2Fb.example"
	if got != want {
		t.Errorf("EncodeURL() = %q, want %q", got, want)
	}
}

func TestDecodeURLVariants(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Address
	}{
		{
			name:  "unescaped relay value",
			input: URLPrefix + testPubKey + "?relay=wss://relay.example.com",
			want:  Address{PublicKey: testPubKey, Relays: []string{"wss://relay.example.com"}},
		},
		{
			name:  "uppercase public key is normalized",
			input: URLPrefix + strings.ToUpper(testPubKey),
			want:  Address{PublicKey: testPubKey},
		},
		{
			name:  "trailing slash and fragment are ignored",
			input: URLPrefix + testPubKey + "/#anchor",
			want:  Address{PublicKey: testPubKey},
		},
		{
			name:  "surrounding whitespace is trimmed",
			input: "  " + URLPrefix + testPubKey + "  ",
			want:  Address{PublicKey: testPubKey},
		},
		{
			name:  "unknown query parameters are ignored",
			input: URLPrefix + testPubKey + "?foo=bar&relay=wss://a.example",
			want:  Address{PublicKey: testPubKey, Relays: []string{"wss://a.example"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.input)
			if err != nil {
				t.Fatalf("Decode(%q) error = %v", tt.input, err)
			}
			assertAddressEqual(t, got, tt.want)
		})
	}
}

func TestDecodeBech32IgnoresUnknownTLV(t *testing.T) {
	pubKey := mustDecodeHex(t, testPubKey)
	relay := "wss://relay.example.com"

	tlv := []byte{tlvTypeSpecial, byte(len(pubKey))}
	tlv = append(tlv, pubKey...)
	tlv = append(tlv, 99, 3, 'a', 'b', 'c') // an unknown type, must be skipped
	tlv = append(tlv, tlvTypeRelay, byte(len(relay)))
	tlv = append(tlv, relay...)

	got, err := DecodeBech32(mustEncodeBech32(t, tlv))
	if err != nil {
		t.Fatalf("DecodeBech32() error = %v", err)
	}
	assertAddressEqual(t, got, Address{PublicKey: testPubKey, Relays: []string{relay}})
}

func TestDecodeBech32Errors(t *testing.T) {
	pubKey := mustDecodeHex(t, testPubKey)

	noPubKey := []byte{tlvTypeRelay, 5}
	noPubKey = append(noPubKey, "wss:/"...)

	twoPubKeys := []byte{tlvTypeSpecial, byte(len(pubKey))}
	twoPubKeys = append(twoPubKeys, pubKey...)
	twoPubKeys = append(twoPubKeys, tlvTypeSpecial, byte(len(pubKey)))
	twoPubKeys = append(twoPubKeys, pubKey...)

	shortPubKey := []byte{tlvTypeSpecial, 4, 1, 2, 3, 4}

	truncated := []byte{tlvTypeSpecial, byte(len(pubKey))}
	truncated = append(truncated, pubKey[:10]...)

	emptyRelay := []byte{tlvTypeSpecial, byte(len(pubKey))}
	emptyRelay = append(emptyRelay, pubKey...)
	emptyRelay = append(emptyRelay, tlvTypeRelay, 0)

	tests := []struct {
		name  string
		input string
	}{
		{"not bech32 at all", "definitely not an address"},
		{"wrong human readable part", mustEncodeBech32WithHRP(t, "npub", pubKey)},
		{"no public key", mustEncodeBech32(t, noPubKey)},
		{"two public keys", mustEncodeBech32(t, twoPubKeys)},
		{"public key of the wrong length", mustEncodeBech32(t, shortPubKey)},
		{"truncated TLV value", mustEncodeBech32(t, truncated)},
		{"empty relay url", mustEncodeBech32(t, emptyRelay)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeBech32(tt.input); err == nil {
				t.Errorf("DecodeBech32(%q) = nil error, want an error", tt.input)
			}
		})
	}
}

func TestDecodeURLErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"missing prefix", "https://relay.example.com"},
		{"missing public key", URLPrefix},
		{"public key too short", URLPrefix + testPubKey[:62]},
		{"public key is not hex", URLPrefix + strings.Repeat("z", 64)},
		{"empty relay", URLPrefix + testPubKey + "?relay="},
		{"relay with a space", URLPrefix + testPubKey + "?relay=wss://a b"},
		{"invalid percent escape in query", URLPrefix + testPubKey + "?relay=%zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DecodeURL(tt.input); err == nil {
				t.Errorf("DecodeURL(%q) = nil error, want an error", tt.input)
			}
		})
	}
}

func TestDecodeUnrecognizedFormat(t *testing.T) {
	for _, input := range []string{"", "npub1abcdef", "http://relay.example.com", "nrvrelay"} {
		if _, err := Decode(input); err == nil {
			t.Errorf("Decode(%q) = nil error, want an error", input)
		}
	}
}

func TestValidateAndEncodeErrors(t *testing.T) {
	tests := []struct {
		name string
		addr Address
	}{
		{"missing public key", Address{}},
		{"public key too long", Address{PublicKey: testPubKey + "00"}},
		{"public key is not hex", Address{PublicKey: strings.Repeat("g", 64)}},
		{"empty relay", Address{PublicKey: testPubKey, Relays: []string{""}}},
		{"relay longer than 255 bytes", Address{PublicKey: testPubKey, Relays: []string{"wss://" + strings.Repeat("a", 250)}}},
		{"relay with a space", Address{PublicKey: testPubKey, Relays: []string{"wss://a b"}}},
		{"relay with a non-ascii rune", Address{PublicKey: testPubKey, Relays: []string{"wss://relay.exämple.com"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.addr.Validate(); err == nil {
				t.Errorf("Validate() = nil error, want an error")
			}
			if _, err := EncodeBech32(tt.addr); err == nil {
				t.Errorf("EncodeBech32() = nil error, want an error")
			}
			if _, err := EncodeURL(tt.addr); err == nil {
				t.Errorf("EncodeURL() = nil error, want an error")
			}
			if _, _, err := Encode(tt.addr); err == nil {
				t.Errorf("Encode() = nil error, want an error")
			}
		})
	}
}

func TestEncodeBech32LongerThan90Characters(t *testing.T) {
	// BIP-173 caps bech32 strings at 90 characters; NIP-19 style addresses
	// with several relays exceed that and must still encode and decode.
	addr := Address{PublicKey: testPubKey, Relays: []string{
		"wss://relay.damus.io",
		"wss://nos.lol",
		"wss://relay.nostr.band",
		"wss://nostr.wine",
	}}

	encoded, err := EncodeBech32(addr)
	if err != nil {
		t.Fatalf("EncodeBech32() error = %v", err)
	}
	if len(encoded) <= 90 {
		t.Fatalf("encoded address is %d characters, expected the test case to exceed 90", len(encoded))
	}

	got, err := DecodeBech32(encoded)
	if err != nil {
		t.Fatalf("DecodeBech32() error = %v", err)
	}
	assertAddressEqual(t, got, addr)
}

func assertAddressEqual(t *testing.T, got, want Address) {
	t.Helper()
	if got.PublicKey != want.PublicKey {
		t.Errorf("PublicKey = %q, want %q", got.PublicKey, want.PublicKey)
	}
	if len(got.Relays) != len(want.Relays) {
		t.Fatalf("Relays = %q, want %q", got.Relays, want.Relays)
	}
	for i := range want.Relays {
		if got.Relays[i] != want.Relays[i] {
			t.Errorf("Relays[%d] = %q, want %q", i, got.Relays[i], want.Relays[i])
		}
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	key, err := decodePubKey(s)
	if err != nil {
		t.Fatalf("decodePubKey(%q) error = %v", s, err)
	}
	return key
}

func mustEncodeBech32(t *testing.T, tlv []byte) string {
	t.Helper()
	return mustEncodeBech32WithHRP(t, HRP, tlv)
}

func mustEncodeBech32WithHRP(t *testing.T, hrp string, payload []byte) string {
	t.Helper()
	data, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		t.Fatalf("bech32.ConvertBits() error = %v", err)
	}
	encoded, err := bech32.Encode(hrp, data)
	if err != nil {
		t.Fatalf("bech32.Encode() error = %v", err)
	}
	return encoded
}
