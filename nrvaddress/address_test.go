package nrvaddress

import "testing"

// The known-good values this file pins down: one hidden relay address in all
// of its representations.
const (
	testPubKey = "b118c8f2b6f8219ff6ffeb3ed4898babd51cef2d39914fa07ab0331e0f19902b"
	testRelay  = "wss://nos.lol"

	testBech32 = "nrv1qqstzxxg72m0sgvl7ml7k0k53x96h4guauknny205patqvc7puveq2cpp4mhxue69uhkummn9ekx7mqtlqnte"
)

func testAddress() Address {
	return Address{PublicKey: testPubKey, Relays: []string{testRelay}}
}

func TestEncode(t *testing.T) {
	encoded, err := Encode(testAddress())
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded != testBech32 {
		t.Errorf("Encode() = %q, want %q", encoded, testBech32)
	}
}

func TestDecode(t *testing.T) {
	got, err := Decode(testBech32)
	if err != nil {
		t.Fatalf("Decode(%q) error = %v", testBech32, err)
	}
	want := testAddress()
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
