// Package nrvaddress implements encoding and decoding of hidden/virtual
// relay addresses as described in the "Nip for Virtual/Hidden Relays".
//
// An address has a single representation, a bech32 string in the style of
// NIP-19:
//
//	nrv1...
//
// It carries the 32-byte public key of the hidden relay and its rendezvous
// relays, in the TLV layout of NIP-19: type 0 holds the 32 raw bytes of the
// public key, type 1 holds one rendezvous relay each (ASCII, may occur
// multiple times).
//
// A hidden relay is referenced in events requiring an "r" tag as
// ["r", "nrv1..."].
package nrvaddress

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

const (
	// HRP is the bech32 human readable part of a hidden relay address.
	HRP = "nrv"

	// Prefix is the start of every hidden relay address: the human readable
	// part plus the bech32 separator.
	Prefix = HRP + "1"

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

// Encode renders the address as an "nrv1..." bech32 string.
func Encode(a Address) (string, error) {
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
	// BIP-173 addresses, nrv strings may exceed 90 characters.
	return bech32.Encode(HRP, data)
}

// Decode parses an "nrv1..." bech32 string.
func Decode(s string) (Address, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), Prefix) {
		return Address{}, fmt.Errorf("unrecognized hidden relay address: expected a %q address", Prefix+"...")
	}

	hrp, data, err := bech32.DecodeNoLimit(s)
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
