// Package nrvevent implements the nostr events of the "Nip for Virtual/Hidden
// Relays": the announcement events a hidden relay publishes about itself and
// the communication events client and relay exchange over their rendezvous
// relays.
//
//	kind 10112  rendezvous list, the relays a hidden relay listens on (announce.go)
//	kind 10113  relay information, a NIP-11 document plus supported encryption (announce.go)
//	kind 27901  nrv communication, encrypted nostr protocol messages (messages.go)
//
// The three types RendezvousList, RelayInfo and MessageEvent are the decoded
// forms of those events. Each of them can be turned into a signed
// github.com/nbd-wtf/go-nostr Event with Sign, and recovered from one with the
// matching Parse function.
//
// This file holds what the event kinds have in common: the kind and tag names,
// the encryption schemes selected by the "encryption" tag, and the validation
// helpers.
package nrvevent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// Event kinds of this NIP. 10112 and 10113 are replaceable kinds as defined in
// NIP-01, 27901 is an ephemeral one.
const (
	// KindRendezvousList is the kind of the event listing the relays a hidden
	// relay listens on.
	KindRendezvousList = 10112

	// KindRelayInfo is the kind of the event carrying the NIP-11 relay
	// information document of a hidden relay.
	KindRelayInfo = 10113

	// KindMessage is the kind of the nrv communication event.
	KindMessage = 27901
)

// Tag names used by the events of this NIP.
const (
	// TagRecipient marks the public key a communication event is addressed to.
	TagRecipient = "p"

	// TagRelay marks a rendezvous relay of a hidden relay.
	TagRelay = "r"

	// TagEncryption marks an encryption scheme, as in the NIP-47 info event.
	TagEncryption = "encryption"
)

// Names of the encryption schemes, as they appear in an "encryption" tag.
const (
	EncryptionNIP44v2 = "nip44_v2"
	EncryptionNIP04   = "nip04"
)

// A Cipher encrypts and decrypts the content of an event of this NIP. Its Name
// is the value written to the "encryption" tag, so that the receiver can pick
// the matching Cipher.
//
// Both sides of a conversation derive the same key from their own secret key
// and the public key of the peer, so Encrypt and Decrypt take the same pair of
// keys on either end.
type Cipher interface {
	// Name is the value of the "encryption" tag, e.g. "nip44_v2".
	Name() string

	// Encrypt encrypts plaintext for the holder of peerPublicKey.
	Encrypt(plaintext, secretKey, peerPublicKey string) (string, error)

	// Decrypt reverses Encrypt.
	Decrypt(ciphertext, secretKey, peerPublicKey string) (string, error)
}

// The ciphers this package implements.
var (
	// NIP44v2 is versioned encryption as defined in NIP-44, the scheme this
	// package uses unless told otherwise.
	NIP44v2 Cipher = nip44v2Cipher{}

	// NIP04 is the legacy encryption of NIP-04. It is offered for relays that
	// cannot do better; new deployments should use NIP44v2.
	NIP04 Cipher = nip04Cipher{}
)

// DefaultCipher is used for events that carry no "encryption" tag.
var DefaultCipher = NIP44v2

var (
	ciphersMu sync.RWMutex
	ciphers   = map[string]Cipher{
		EncryptionNIP44v2: NIP44v2,
		EncryptionNIP04:   NIP04,
	}
)

// RegisterCipher makes c available to the Parse functions under c.Name(),
// replacing any cipher registered under that name before. It is meant for
// encryption schemes this package does not implement itself.
func RegisterCipher(c Cipher) error {
	if c == nil {
		return errors.New("nil cipher")
	}
	if c.Name() == "" {
		return errors.New("cipher has no name")
	}
	ciphersMu.Lock()
	defer ciphersMu.Unlock()
	ciphers[c.Name()] = c
	return nil
}

// LookupCipher returns the cipher registered under name.
func LookupCipher(name string) (Cipher, bool) {
	ciphersMu.RLock()
	defer ciphersMu.RUnlock()
	c, ok := ciphers[name]
	return c, ok
}

// RegisteredCiphers lists the names of all known ciphers, sorted.
func RegisteredCiphers() []string {
	ciphersMu.RLock()
	defer ciphersMu.RUnlock()
	names := make([]string, 0, len(ciphers))
	for name := range ciphers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// cipherFor resolves the value of an "encryption" tag. An empty name selects
// DefaultCipher.
func cipherFor(name string) (Cipher, error) {
	if name == "" {
		return DefaultCipher, nil
	}
	c, ok := LookupCipher(name)
	if !ok {
		return nil, fmt.Errorf("unsupported encryption %q, known schemes are %s", name, strings.Join(RegisteredCiphers(), ", "))
	}
	return c, nil
}

type nip44v2Cipher struct{}

func (nip44v2Cipher) Name() string { return EncryptionNIP44v2 }

func (nip44v2Cipher) Encrypt(plaintext, secretKey, peerPublicKey string) (string, error) {
	key, err := nip44.GenerateConversationKey(peerPublicKey, secretKey)
	if err != nil {
		return "", fmt.Errorf("deriving nip44 conversation key: %w", err)
	}
	ciphertext, err := nip44.Encrypt(plaintext, key)
	if err != nil {
		return "", fmt.Errorf("nip44 encryption: %w", err)
	}
	return ciphertext, nil
}

func (nip44v2Cipher) Decrypt(ciphertext, secretKey, peerPublicKey string) (string, error) {
	key, err := nip44.GenerateConversationKey(peerPublicKey, secretKey)
	if err != nil {
		return "", fmt.Errorf("deriving nip44 conversation key: %w", err)
	}
	plaintext, err := nip44.Decrypt(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("nip44 decryption: %w", err)
	}
	return plaintext, nil
}

type nip04Cipher struct{}

func (nip04Cipher) Name() string { return EncryptionNIP04 }

func (nip04Cipher) Encrypt(plaintext, secretKey, peerPublicKey string) (string, error) {
	secret, err := nip04.ComputeSharedSecret(peerPublicKey, secretKey)
	if err != nil {
		return "", fmt.Errorf("deriving nip04 shared secret: %w", err)
	}
	ciphertext, err := nip04.Encrypt(plaintext, secret)
	if err != nil {
		return "", fmt.Errorf("nip04 encryption: %w", err)
	}
	return ciphertext, nil
}

func (nip04Cipher) Decrypt(ciphertext, secretKey, peerPublicKey string) (string, error) {
	secret, err := nip04.ComputeSharedSecret(peerPublicKey, secretKey)
	if err != nil {
		return "", fmt.Errorf("deriving nip04 shared secret: %w", err)
	}
	plaintext, err := nip04.Decrypt(ciphertext, secret)
	if err != nil {
		return "", fmt.Errorf("nip04 decryption: %w", err)
	}
	return plaintext, nil
}

// ValidatePublicKey reports whether pk is a 32-byte public key in lowercase
// hex, the form every public key takes in a nostr event.
func ValidatePublicKey(pk string) error {
	return validateKey(pk, "public key")
}

// ValidateSecretKey reports whether sk is a 32-byte secret key in hex.
func ValidateSecretKey(sk string) error {
	return validateKey(sk, "secret key")
}

func validateKey(key, what string) error {
	if key == "" {
		return fmt.Errorf("missing %s", what)
	}
	if len(key) != 64 {
		return fmt.Errorf("%s must be 64 hex characters, got %d", what, len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		return fmt.Errorf("%s is not valid hex: %w", what, err)
	}
	if strings.ToLower(key) != key {
		return fmt.Errorf("%s must be lowercase hex", what)
	}
	return nil
}

// ValidateRelayURL reports whether relay is usable as a rendezvous point: a
// websocket url that fits into the TLV entry of an nrvrelay1... address.
func ValidateRelayURL(relay string) error {
	if relay == "" {
		return errors.New("empty relay url")
	}
	// A TLV entry of an nrvrelay1... address carries its length in one byte.
	if len(relay) > 255 {
		return fmt.Errorf("relay url is %d bytes, the maximum is 255", len(relay))
	}
	for i := 0; i < len(relay); i++ {
		if relay[i] < 0x21 || relay[i] > 0x7e {
			return fmt.Errorf("relay url %q contains a character that is not printable ASCII", relay)
		}
	}
	parsed, err := url.Parse(relay)
	if err != nil {
		return fmt.Errorf("relay url %q is not a url: %w", relay, err)
	}
	if scheme := strings.ToLower(parsed.Scheme); scheme != "ws" && scheme != "wss" {
		return fmt.Errorf("relay url %q must use the ws:// or wss:// scheme", relay)
	}
	if parsed.Host == "" {
		return fmt.Errorf("relay url %q has no host", relay)
	}
	return nil
}

// Verify checks the id and the signature of an event. The Parse functions of
// this package do not verify signatures themselves, as events coming from a
// relay connection have usually been verified already.
func Verify(evt *nostr.Event) error {
	if evt == nil {
		return errors.New("nil event")
	}
	if !evt.CheckID() {
		return fmt.Errorf("event id %q does not match its content", evt.ID)
	}
	ok, err := evt.CheckSignature()
	if err != nil {
		return fmt.Errorf("checking signature of event %s: %w", evt.ID, err)
	}
	if !ok {
		return fmt.Errorf("invalid signature on event %s", evt.ID)
	}
	return nil
}

// checkKind reports whether evt can be parsed as an event of the given kind.
func checkKind(evt *nostr.Event, kind int) error {
	if evt == nil {
		return errors.New("nil event")
	}
	if evt.Kind != kind {
		return fmt.Errorf("event is of kind %d, want %d", evt.Kind, kind)
	}
	return nil
}

// sign fills in pubkey, id and signature of evt.
func sign(evt *nostr.Event, secretKey string) error {
	if err := ValidateSecretKey(secretKey); err != nil {
		return err
	}
	if evt.CreatedAt == 0 {
		evt.CreatedAt = nostr.Now()
	}
	if err := evt.Sign(secretKey); err != nil {
		return fmt.Errorf("signing kind %d event: %w", evt.Kind, err)
	}
	return nil
}

// tagValues returns every value of every tag with the given name, in order,
// skipping empty ones. Tags may carry more than one value, as in
// ["encryption", "nip44_v2", "nip04"].
func tagValues(tags nostr.Tags, name string) []string {
	var values []string
	for _, tag := range tags {
		if len(tag) < 2 || tag[0] != name {
			continue
		}
		for _, value := range tag[1:] {
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

// firstTagValue returns the first value of the first tag with the given name.
func firstTagValue(tags nostr.Tags, name string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag[1]
		}
	}
	return ""
}
