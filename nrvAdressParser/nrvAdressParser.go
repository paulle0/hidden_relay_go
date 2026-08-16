// Package nrvaddressparser implements encoding and decoding of hidden/virtual
// relay addresses as described in the "Nip for Virtual/Hidden Relays".
//
// Two representations of the same data are supported:
//
//	bech32 (NIP-19 style):  nrvrelay1...
//	url:                    nostr+nrv://<hexpubkey>?relay=<relay1>&relay=<relay2>
//
// Both carry the 32-byte public key of the hidden relay and its rendezvous
// relays. The bech32 form uses the TLV layout of NIP-19: type 0 holds the
// 32 raw bytes of the public key, type 1 holds one rendezvous relay each
// (ASCII, may occur multiple times).
package nrvaddressparser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

const (
	// HRP is the bech32 human readable part of a hidden relay address.
	HRP = "nrvrelay"

	// URLScheme is the scheme of the url representation, without "://".
	URLScheme = "nostr+nrv"

	// URLPrefix is the full prefix of the url representation.
	URLPrefix = URLScheme + "://"

	tlvTypeSpecial = 0 // 32 bytes public key
	tlvTypeRelay   = 1 // one rendezvous relay, ASCII
)

// Address is a hidden/virtual relay reference: the relay's public key plus the
// rendezvous relays it listens on.
type Address struct {
	// PublicKey is the 32-byte public key of the hidden relay, lowercase hex.
	PublicKey string

	// Relays are the rendezvous relays, in the order they were encoded.
	Relays []string
}

// Validate reports whether the address can be encoded.
func (a Address) Validate() error {
	if _, err := decodePubKey(a.PublicKey); err != nil {
		return err
	}
	for _, relay := range a.Relays {
		if err := validateRelay(relay); err != nil {
			return err
		}
	}
	return nil
}

// Encode returns both representations of the address.
func Encode(a Address) (bech32Addr, urlAddr string, err error) {
	bech32Addr, err = EncodeBech32(a)
	if err != nil {
		return "", "", err
	}
	urlAddr, err = EncodeURL(a)
	if err != nil {
		return "", "", err
	}
	return bech32Addr, urlAddr, nil
}

// Decode parses either representation, picking the format from the input.
func Decode(s string) (Address, error) {
	trimmed := strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(strings.ToLower(trimmed), URLPrefix):
		return DecodeURL(trimmed)
	case strings.HasPrefix(strings.ToLower(trimmed), HRP+"1"):
		return DecodeBech32(trimmed)
	default:
		return Address{}, fmt.Errorf("unrecognized hidden relay address: expected a %q or %q address", HRP+"1...", URLPrefix+"...")
	}
}

// EncodeBech32 renders the address as an "nrvrelay1..." bech32 string.
func EncodeBech32(a Address) (string, error) {
	pubKey, err := decodePubKey(a.PublicKey)
	if err != nil {
		return "", err
	}

	tlv := make([]byte, 0, 34+len(a.Relays)*32)
	tlv = append(tlv, tlvTypeSpecial, byte(len(pubKey)))
	tlv = append(tlv, pubKey...)
	for _, relay := range a.Relays {
		if err := validateRelay(relay); err != nil {
			return "", err
		}
		tlv = append(tlv, tlvTypeRelay, byte(len(relay)))
		tlv = append(tlv, relay...)
	}

	data, err := bech32.ConvertBits(tlv, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("converting address to bech32 data: %w", err)
	}
	// bech32.Encode imposes no length limit, which is what NIP-19 needs: unlike
	// BIP-173 addresses, nrvrelay strings may exceed 90 characters.
	return bech32.Encode(HRP, data)
}

// DecodeBech32 parses an "nrvrelay1..." bech32 string.
func DecodeBech32(s string) (Address, error) {
	hrp, data, err := bech32.DecodeNoLimit(strings.TrimSpace(s))
	if err != nil {
		return Address{}, fmt.Errorf("invalid bech32 string: %w", err)
	}
	if hrp != HRP {
		return Address{}, fmt.Errorf("unexpected bech32 prefix %q, want %q", hrp, HRP)
	}

	tlv, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return Address{}, fmt.Errorf("invalid bech32 payload: %w", err)
	}

	var (
		addr      Address
		gotPubKey bool
	)
	for len(tlv) > 0 {
		if len(tlv) < 2 {
			return Address{}, errors.New("truncated TLV entry")
		}
		typ, length := tlv[0], int(tlv[1])
		if len(tlv) < 2+length {
			return Address{}, fmt.Errorf("TLV entry of type %d claims %d bytes, only %d available", typ, length, len(tlv)-2)
		}
		value := tlv[2 : 2+length]
		tlv = tlv[2+length:]

		switch typ {
		case tlvTypeSpecial:
			if gotPubKey {
				return Address{}, errors.New("more than one public key in address")
			}
			if length != 32 {
				return Address{}, fmt.Errorf("public key must be 32 bytes, got %d", length)
			}
			addr.PublicKey = hex.EncodeToString(value)
			gotPubKey = true
		case tlvTypeRelay:
			relay := string(value)
			if err := validateRelay(relay); err != nil {
				return Address{}, err
			}
			addr.Relays = append(addr.Relays, relay)
		default:
			// Unknown TLV types are ignored, as recommended by NIP-19.
		}
	}
	if !gotPubKey {
		return Address{}, errors.New("address contains no public key")
	}
	return addr, nil
}

// EncodeURL renders the address as a "nostr+nrv://..." url.
func EncodeURL(a Address) (string, error) {
	if _, err := decodePubKey(a.PublicKey); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(URLPrefix)
	b.WriteString(strings.ToLower(a.PublicKey))
	for i, relay := range a.Relays {
		if err := validateRelay(relay); err != nil {
			return "", err
		}
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString("relay=")
		b.WriteString(url.QueryEscape(relay))
	}
	return b.String(), nil
}

// DecodeURL parses a "nostr+nrv://..." url. Relay values may be percent-encoded
// or given verbatim.
func DecodeURL(s string) (Address, error) {
	s = strings.TrimSpace(s)
	if len(s) < len(URLPrefix) || !strings.EqualFold(s[:len(URLPrefix)], URLPrefix) {
		return Address{}, fmt.Errorf("missing %q prefix", URLPrefix)
	}
	rest := s[len(URLPrefix):]

	pubKeyPart, query, _ := strings.Cut(rest, "?")
	pubKeyPart, _, _ = strings.Cut(pubKeyPart, "#")
	pubKeyPart = strings.TrimSuffix(pubKeyPart, "/")
	if _, err := decodePubKey(pubKeyPart); err != nil {
		return Address{}, err
	}

	addr := Address{PublicKey: strings.ToLower(pubKeyPart)}
	if query == "" {
		return addr, nil
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return Address{}, fmt.Errorf("invalid query %q: %w", query, err)
	}
	for _, relay := range values["relay"] {
		if err := validateRelay(relay); err != nil {
			return Address{}, err
		}
		addr.Relays = append(addr.Relays, relay)
	}
	return addr, nil
}

func decodePubKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("missing public key")
	}
	if len(s) != 64 {
		return nil, fmt.Errorf("public key must be 64 hex characters, got %d", len(s))
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid hex: %w", err)
	}
	return key, nil
}

func validateRelay(relay string) error {
	if relay == "" {
		return errors.New("empty relay url")
	}
	// A TLV entry carries its length in a single byte.
	if len(relay) > 255 {
		return fmt.Errorf("relay url is %d bytes, the maximum is 255", len(relay))
	}
	for i := 0; i < len(relay); i++ {
		if relay[i] < 0x21 || relay[i] > 0x7e {
			return fmt.Errorf("relay url %q contains a character that is not printable ASCII", relay)
		}
	}
	return nil
}
