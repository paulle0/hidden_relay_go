// What a "Virtual/Hidden Relay" publishes about itself: the kind 10112 event
// listing the rendezvous relays it listens on, and the kind 10113 event
// carrying its NIP-11 relay information document. Both are replaceable kinds,
// so a relay has at most one of each.

package nrvevent

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip11"

	"github.com/paulle0/hidden_relay_go/nrvaddress"
)

// RendezvousList is the decoded form of a kind 10112 event: the relays on
// which a hidden relay listens for requests and sends responses. The event
// follows the shape of the relay lists of NIP-65 and NIP-51 and signals that
// the public key is reachable there.
type RendezvousList struct {
	// PubKey is the public key of the hidden relay, in lowercase hex.
	// ParseRendezvousList fills it in; Sign derives it from the secret key and
	// leaves this field alone.
	PubKey string

	// Relays are the rendezvous relays, one per "r" tag, in order.
	Relays []string

	// CreatedAt is the timestamp of the event. Sign uses the current time when
	// this is zero.
	CreatedAt nostr.Timestamp
}

// NewRendezvousList returns the rendezvous list of a hidden relay.
func NewRendezvousList(relays ...string) *RendezvousList {
	return &RendezvousList{Relays: relays}
}

// Validate reports whether the list can be signed.
func (r *RendezvousList) Validate() error {
	if r.PubKey != "" {
		if err := ValidatePublicKey(r.PubKey); err != nil {
			return fmt.Errorf("hidden relay: %w", err)
		}
	}
	if len(r.Relays) == 0 {
		return errors.New("rendezvous list contains no relays")
	}
	seen := make(map[string]bool, len(r.Relays))
	for _, relay := range r.Relays {
		if err := ValidateRelayURL(relay); err != nil {
			return err
		}
		if seen[relay] {
			return fmt.Errorf("relay %q is listed twice", relay)
		}
		seen[relay] = true
	}
	return nil
}

// Sign returns the signed kind 10112 event of the list. The secret key belongs
// to the hidden relay.
func (r *RendezvousList) Sign(secretKey string) (*nostr.Event, error) {
	if err := ValidateSecretKey(secretKey); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}

	tags := make(nostr.Tags, 0, len(r.Relays))
	for _, relay := range r.Relays {
		tags = append(tags, nostr.Tag{TagRelay, relay})
	}

	event := &nostr.Event{
		CreatedAt: r.CreatedAt,
		Kind:      KindRendezvousList,
		Tags:      tags,
		Content:   "",
	}
	if err := sign(event, secretKey); err != nil {
		return nil, err
	}
	return event, nil
}

// ParseRendezvousList reads a kind 10112 event. Tags other than "r" are
// ignored, so that the event can grow in the way NIP-65 events do.
//
// The signature of the event is not checked, see Verify.
func ParseRendezvousList(event *nostr.Event) (*RendezvousList, error) {
	if err := checkKind(event, KindRendezvousList); err != nil {
		return nil, err
	}
	if err := ValidatePublicKey(event.PubKey); err != nil {
		return nil, fmt.Errorf("hidden relay: %w", err)
	}

	list := &RendezvousList{
		PubKey:    event.PubKey,
		Relays:    tagValues(event.Tags, TagRelay),
		CreatedAt: event.CreatedAt,
	}
	if len(list.Relays) == 0 {
		return nil, fmt.Errorf("event %s lists no rendezvous relay", event.ID)
	}
	for _, relay := range list.Relays {
		if err := ValidateRelayURL(relay); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// Address turns the list into the hidden relay address that a client puts into
// an "r" tag or displays as an nrvrelay1... string.
func (r *RendezvousList) Address() (nrvaddress.Address, error) {
	if err := ValidatePublicKey(r.PubKey); err != nil {
		return nrvaddress.Address{}, fmt.Errorf("hidden relay: %w", err)
	}
	address := nrvaddress.Address{PublicKey: r.PubKey, Relays: r.Relays}
	if err := address.Validate(); err != nil {
		return nrvaddress.Address{}, err
	}
	return address, nil
}

// RendezvousListFrom builds a rendezvous list from a hidden relay address, the
// way a client would after decoding an nrvrelay1... string.
func RendezvousListFrom(address nrvaddress.Address) *RendezvousList {
	return &RendezvousList{PubKey: address.PublicKey, Relays: address.Relays}
}

// RendezvousListFilter returns a filter for the kind 10112 events of the given
// hidden relays.
func RendezvousListFilter(pubKeys ...string) nostr.Filter {
	return announceFilter(KindRendezvousList, pubKeys)
}

// RelayInfo is the decoded form of a kind 10113 event: the NIP-11 relay
// information document of a hidden relay, together with the encryption schemes
// it accepts for communication events.
type RelayInfo struct {
	// PubKey is the public key of the hidden relay, in lowercase hex.
	// ParseRelayInfo fills it in; Sign derives it from the secret key and
	// leaves this field alone.
	PubKey string

	// Encryption lists the supported encryption schemes, e.g. "nip44_v2", as
	// given by the "encryption" tags. Sign writes one tag per scheme and falls
	// back to DefaultCipher when the list is empty.
	Encryption []string

	// Document is the NIP-11 relay information document of the content.
	Document nip11.RelayInformationDocument

	// Raw is the content as it stood in the event. ParseRelayInfo fills it in
	// and Sign prefers it over Document, so that fields this package does not
	// know about survive a round trip. Clear it to publish Document instead.
	Raw json.RawMessage

	// CreatedAt is the timestamp of the event. Sign uses the current time when
	// this is zero.
	CreatedAt nostr.Timestamp
}

// NewRelayInfo returns the relay information of a hidden relay. Without an
// encryption scheme the event announces DefaultCipher.
func NewRelayInfo(document nip11.RelayInformationDocument, encryption ...string) *RelayInfo {
	return &RelayInfo{Encryption: encryption, Document: document}
}

// Validate reports whether the relay information can be signed.
func (r *RelayInfo) Validate() error {
	if r.PubKey != "" {
		if err := ValidatePublicKey(r.PubKey); err != nil {
			return fmt.Errorf("hidden relay: %w", err)
		}
	}
	seen := make(map[string]bool, len(r.Encryption))
	for _, encryption := range r.Encryption {
		if encryption == "" {
			return errors.New("empty encryption scheme")
		}
		if seen[encryption] {
			return fmt.Errorf("encryption %q is listed twice", encryption)
		}
		seen[encryption] = true
	}
	if len(r.Raw) > 0 && !json.Valid(r.Raw) {
		return errors.New("relay information document is not valid JSON")
	}
	return nil
}

// Supports reports whether the hidden relay accepts the named encryption
// scheme. A relay that announces no scheme at all is taken to accept
// DefaultCipher, the scheme this package uses when no "encryption" tag is
// present.
func (r *RelayInfo) Supports(encryption string) bool {
	if len(r.Encryption) == 0 {
		return encryption == DefaultCipher.Name()
	}
	for _, supported := range r.Encryption {
		if supported == encryption {
			return true
		}
	}
	return false
}

// SelectCipher returns the first announced encryption scheme this package can
// speak, so that a client can encrypt its communication events accordingly.
func (r *RelayInfo) SelectCipher() (Cipher, error) {
	if len(r.Encryption) == 0 {
		return DefaultCipher, nil
	}
	for _, encryption := range r.Encryption {
		if cipher, ok := LookupCipher(encryption); ok {
			return cipher, nil
		}
	}
	return nil, fmt.Errorf("hidden relay announces %s, none of which is supported; known schemes are %s",
		strings.Join(r.Encryption, ", "), strings.Join(RegisteredCiphers(), ", "))
}

// Content returns the NIP-11 document as it goes into the event.
func (r *RelayInfo) Content() (string, error) {
	if len(r.Raw) > 0 {
		if !json.Valid(r.Raw) {
			return "", errors.New("relay information document is not valid JSON")
		}
		return string(r.Raw), nil
	}
	document, err := json.Marshal(r.Document)
	if err != nil {
		return "", fmt.Errorf("encoding relay information document: %w", err)
	}
	return string(document), nil
}

// Sign returns the signed kind 10113 event. The secret key belongs to the
// hidden relay.
func (r *RelayInfo) Sign(secretKey string) (*nostr.Event, error) {
	if err := ValidateSecretKey(secretKey); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	content, err := r.Content()
	if err != nil {
		return nil, err
	}

	encryption := r.Encryption
	if len(encryption) == 0 {
		encryption = []string{DefaultCipher.Name()}
	}
	tags := make(nostr.Tags, 0, len(encryption))
	for _, scheme := range encryption {
		tags = append(tags, nostr.Tag{TagEncryption, scheme})
	}

	event := &nostr.Event{
		CreatedAt: r.CreatedAt,
		Kind:      KindRelayInfo,
		Tags:      tags,
		Content:   content,
	}
	if err := sign(event, secretKey); err != nil {
		return nil, err
	}
	return event, nil
}

// ParseRelayInfo reads a kind 10113 event. An "encryption" tag may name more
// than one scheme, and the event may carry more than one such tag.
//
// The signature of the event is not checked, see Verify.
func ParseRelayInfo(event *nostr.Event) (*RelayInfo, error) {
	if err := checkKind(event, KindRelayInfo); err != nil {
		return nil, err
	}
	if err := ValidatePublicKey(event.PubKey); err != nil {
		return nil, fmt.Errorf("hidden relay: %w", err)
	}

	info := &RelayInfo{
		PubKey:     event.PubKey,
		Encryption: tagValues(event.Tags, TagEncryption),
		CreatedAt:  event.CreatedAt,
	}
	if content := strings.TrimSpace(event.Content); content != "" {
		if err := json.Unmarshal([]byte(content), &info.Document); err != nil {
			return nil, fmt.Errorf("content of event %s is not a NIP-11 relay information document: %w", event.ID, err)
		}
		info.Raw = json.RawMessage(content)
	}
	return info, nil
}

// RelayInfoFilter returns a filter for the kind 10113 events of the given
// hidden relays.
func RelayInfoFilter(pubKeys ...string) nostr.Filter {
	return announceFilter(KindRelayInfo, pubKeys)
}

// AnnouncementFilter returns a filter for both announcement kinds of the given
// hidden relays, the one a client uses to discover where and how to reach them.
func AnnouncementFilter(pubKeys ...string) nostr.Filter {
	filter := announceFilter(KindRendezvousList, pubKeys)
	filter.Kinds = []int{KindRendezvousList, KindRelayInfo}
	return filter
}

func announceFilter(kind int, pubKeys []string) nostr.Filter {
	filter := nostr.Filter{Kinds: []int{kind}}
	if len(pubKeys) > 0 {
		filter.Authors = pubKeys
	}
	return filter
}
