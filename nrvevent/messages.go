// Communication between a "Virtual Client" and a "Virtual/Hidden Relay":
// kind 27901 events whose content is an encrypted array of nostr protocol
// messages. Relays treat the kind as ephemeral.

package nrvevent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

const (
	// DefaultMaxContentSize is the ceiling for the encrypted content of a
	// communication event. The NIP asks for a limit around 30 kB so that the
	// event passes through most relays.
	DefaultMaxContentSize = 30 * 1024

	// DefaultMaxPayloadSize is the ceiling Split puts on the plaintext payload
	// of one event. 20 KiB of plaintext pad and base64 to roughly 27 kB of
	// nip44_v2 ciphertext, which stays below DefaultMaxContentSize.
	DefaultMaxPayloadSize = 20 * 1024
)

// A Message is a single message of the nostr protocol as it would travel over
// a websocket connection to a relay, for example ["REQ","sub1",{"kinds":[1]}]
// or ["EVENT","sub1",{...}]. It is kept as raw JSON so that messages of any
// nostr protocol can be carried unchanged.
type Message = json.RawMessage

// MessageEvent is the decoded form of a kind 27901 nrv communication event:
// the messages of its encrypted content plus the keys of the two parties.
type MessageEvent struct {
	// Sender is the public key of the party that signed the event, in
	// lowercase hex. ParseMessageEvent fills it in; Sign derives it from the
	// secret key and leaves this field alone.
	Sender string

	// Recipient is the public key the event is addressed to, in lowercase hex.
	// It is the value of the "p" tag.
	Recipient string

	// Encryption names the scheme used for the content, e.g. "nip44_v2". An
	// empty value selects DefaultCipher.
	Encryption string

	// CreatedAt is the timestamp of the event. Sign uses the current time when
	// this is zero.
	CreatedAt nostr.Timestamp

	// Messages are the nostr protocol messages of the content, in order. An
	// event may carry more than one.
	Messages []Message

	// MaxContentSize limits the size of the encrypted content Sign produces.
	// Zero selects DefaultMaxContentSize, a negative value removes the limit.
	MaxContentSize int
}

// NewMessageEvent returns a communication event addressed to recipient,
// carrying messages and encrypted with DefaultCipher.
func NewMessageEvent(recipient string, messages ...Message) *MessageEvent {
	return &MessageEvent{Recipient: recipient, Messages: messages}
}

// Append adds messages to the event.
func (m *MessageEvent) Append(messages ...Message) {
	m.Messages = append(m.Messages, messages...)
}

// Validate reports whether the event can be signed: a well formed recipient, a
// known encryption scheme and at least one message, each of them a JSON array.
func (m *MessageEvent) Validate() error {
	if err := ValidatePublicKey(m.Recipient); err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	if m.Sender != "" {
		if err := ValidatePublicKey(m.Sender); err != nil {
			return fmt.Errorf("sender: %w", err)
		}
	}
	if _, err := cipherFor(m.Encryption); err != nil {
		return err
	}
	if len(m.Messages) == 0 {
		return errors.New("event carries no messages")
	}
	for i, message := range m.Messages {
		if err := validateMessage(message); err != nil {
			return fmt.Errorf("message %d: %w", i, err)
		}
	}
	return nil
}

// Payload returns the plaintext that gets encrypted into the content of the
// event: the JSON array of the messages.
func (m *MessageEvent) Payload() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, message := range m.Messages {
		if err := validateMessage(message); err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := json.Compact(&buf, message); err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// Envelopes parses the messages of the event into go-nostr envelopes. It fails
// on a message that is not part of the nostr relay protocol, which is not an
// error for the NIP itself: the content may carry messages of another
// protocol, which Messages hands over untouched.
func (m *MessageEvent) Envelopes() ([]nostr.Envelope, error) {
	envelopes := make([]nostr.Envelope, 0, len(m.Messages))
	for i, message := range m.Messages {
		envelope := nostr.ParseMessage(string(message))
		if envelope == nil {
			return nil, fmt.Errorf("message %d is not a known nostr protocol message", i)
		}
		envelopes = append(envelopes, envelope)
	}
	return envelopes, nil
}

// Sign encrypts the messages for the recipient and returns the signed kind
// 27901 event. The secret key belongs to the sender.
func (m *MessageEvent) Sign(secretKey string) (*nostr.Event, error) {
	if err := ValidateSecretKey(secretKey); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	cipher, err := cipherFor(m.Encryption)
	if err != nil {
		return nil, err
	}

	payload, err := m.Payload()
	if err != nil {
		return nil, err
	}
	content, err := cipher.Encrypt(string(payload), secretKey, m.Recipient)
	if err != nil {
		return nil, err
	}
	if limit := m.contentLimit(); limit > 0 && len(content) > limit {
		return nil, fmt.Errorf("encrypted content is %d bytes, the maximum is %d; use Split to spread the messages over several events", len(content), limit)
	}

	event := &nostr.Event{
		CreatedAt: m.CreatedAt,
		Kind:      KindMessage,
		Tags: nostr.Tags{
			{TagRecipient, m.Recipient},
			{TagEncryption, cipher.Name()},
		},
		Content: content,
	}
	if err := sign(event, secretKey); err != nil {
		return nil, err
	}
	return event, nil
}

func (m *MessageEvent) contentLimit() int {
	if m.MaxContentSize == 0 {
		return DefaultMaxContentSize
	}
	return m.MaxContentSize
}

// ParseMessageEvent decrypts a kind 27901 event with secretKey. The key may
// belong to either party: both sides derive the same conversation key, so a
// sender can read back its own events as well as those addressed to it.
//
// The signature of the event is not checked, see Verify.
func ParseMessageEvent(event *nostr.Event, secretKey string) (*MessageEvent, error) {
	if err := checkKind(event, KindMessage); err != nil {
		return nil, err
	}
	if err := ValidateSecretKey(secretKey); err != nil {
		return nil, err
	}
	if err := ValidatePublicKey(event.PubKey); err != nil {
		return nil, fmt.Errorf("sender: %w", err)
	}

	recipient := firstTagValue(event.Tags, TagRecipient)
	if err := ValidatePublicKey(recipient); err != nil {
		return nil, fmt.Errorf("recipient: %w", err)
	}

	encryption := firstTagValue(event.Tags, TagEncryption)
	cipher, err := cipherFor(encryption)
	if err != nil {
		return nil, err
	}

	ourKey, err := nostr.GetPublicKey(secretKey)
	if err != nil {
		return nil, fmt.Errorf("deriving public key from secret key: %w", err)
	}
	var peer string
	switch ourKey {
	case event.PubKey:
		peer = recipient
	case recipient:
		peer = event.PubKey
	default:
		return nil, fmt.Errorf("event %s is neither sent by nor addressed to %s", event.ID, ourKey)
	}

	payload, err := cipher.Decrypt(event.Content, secretKey, peer)
	if err != nil {
		return nil, err
	}
	messages, err := parsePayload([]byte(payload))
	if err != nil {
		return nil, err
	}

	return &MessageEvent{
		Sender:     event.PubKey,
		Recipient:  recipient,
		Encryption: cipher.Name(),
		CreatedAt:  event.CreatedAt,
		Messages:   messages,
	}, nil
}

// IsMessageEvent reports whether event is a kind 27901 event.
func IsMessageEvent(event *nostr.Event) bool {
	return event != nil && event.Kind == KindMessage
}

// MessagesFilter returns a filter for the communication events addressed to
// recipient, optionally restricted to the given senders.
func MessagesFilter(recipient string, senders ...string) nostr.Filter {
	filter := nostr.Filter{
		Kinds: []int{KindMessage},
		Tags:  nostr.TagMap{TagRecipient: []string{recipient}},
	}
	if len(senders) > 0 {
		filter.Authors = senders
	}
	return filter
}

// Split spreads messages over as many communication events as are needed to
// keep the plaintext payload of each event within maxPayloadSize bytes. A
// maxPayloadSize of zero or less selects DefaultMaxPayloadSize.
//
// The messages keep their order, and a message is never cut in half: a single
// message that does not fit on its own is an error.
func Split(recipient string, messages []Message, maxPayloadSize int) ([]*MessageEvent, error) {
	if maxPayloadSize <= 0 {
		maxPayloadSize = DefaultMaxPayloadSize
	}
	// The payload of an event is at least the enclosing "[" and "]".
	budget := maxPayloadSize - 2
	if budget <= 0 {
		return nil, fmt.Errorf("maximum payload of %d bytes is too small to hold a message", maxPayloadSize)
	}

	var (
		events  []*MessageEvent
		current *MessageEvent
		used    int
	)
	for i, message := range messages {
		if err := validateMessage(message); err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, message); err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
		size := compacted.Len()
		if size > budget {
			return nil, fmt.Errorf("message %d is %d bytes and does not fit into a payload of %d bytes", i, size, maxPayloadSize)
		}
		// Every message but the first of an event is preceded by a comma.
		needed := size
		if current != nil {
			needed++
		}
		if current == nil || used+needed > budget {
			current = NewMessageEvent(recipient)
			events = append(events, current)
			used = 0
			needed = size
		}
		current.Append(Message(compacted.Bytes()))
		used += needed
	}
	return events, nil
}

// MessageFromEnvelope renders a go-nostr envelope, e.g. a nostr.ReqEnvelope,
// as a message that can be carried by a communication event.
func MessageFromEnvelope(envelope nostr.Envelope) (Message, error) {
	if envelope == nil {
		return nil, errors.New("nil envelope")
	}
	encoded, err := envelope.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("encoding %s envelope: %w", envelope.Label(), err)
	}
	return Message(encoded), nil
}

// parsePayload reads the decrypted content of a communication event.
func parsePayload(payload []byte) ([]Message, error) {
	var messages []Message
	if err := json.Unmarshal(payload, &messages); err != nil {
		return nil, fmt.Errorf("content is not a JSON array of messages: %w", err)
	}
	if len(messages) == 0 {
		return nil, errors.New("content carries no messages")
	}
	for i, message := range messages {
		if err := validateMessage(message); err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
	}
	return messages, nil
}

// validateMessage reports whether message is a JSON array, the shape every
// message of the nostr protocol has.
func validateMessage(message Message) error {
	trimmed := bytes.TrimLeft(message, " \t\r\n")
	if len(trimmed) == 0 {
		return errors.New("empty message")
	}
	if trimmed[0] != '[' {
		return errors.New("message is not a JSON array")
	}
	if !json.Valid(trimmed) {
		return errors.New("message is not valid JSON")
	}
	return nil
}
