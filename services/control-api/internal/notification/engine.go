package notification

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"strings"
)

type Engine struct {
	catalog *Catalog
	now     Clock
}

func NewEngine(catalog *Catalog, now Clock) (*Engine, error) {
	if catalog == nil || now == nil {
		return nil, ErrInvalidEngine
	}
	return &Engine{catalog: catalog, now: now}, nil
}

func (e *Engine) Plan(request PlanRequest) (Plan, error) {
	if e == nil || e.catalog == nil || e.now == nil {
		return Plan{}, ErrInvalidEngine
	}
	if !validEventIdentity(request.Identity) {
		return Plan{}, ErrInvalidIdentity
	}
	if err := validateContextValidationPolicies(
		request.Identity.EventType, request.Templates, request.Contexts, request.ContextValidationPolicies,
	); err != nil {
		return Plan{}, err
	}
	channels, err := DecideChannels(request.Policy, request.Switches, request.Subscription)
	if err != nil {
		return Plan{}, err
	}
	deliveries := make([]Delivery, 0, len(channels))
	for _, channel := range channels {
		ref, exists := request.Templates[channel]
		if !exists || ref.Channel != channel {
			return Plan{}, ErrTemplateSelection
		}
		message, err := e.catalog.render(ref, request.Contexts[channel], request.ContextValidationPolicies[channel])
		if err != nil {
			return Plan{}, err
		}
		key, err := DedupKey(request.Identity, ref)
		if err != nil {
			return Plan{}, err
		}
		deliveries = append(deliveries, Delivery{
			Channel: channel, Template: ref, Subject: message.Subject, Body: message.Body, DedupKey: key,
		})
	}
	return Plan{CreatedAt: e.now().UTC(), Deliveries: deliveries}, nil
}

func DedupKey(identity EventIdentity, ref TemplateRef) (string, error) {
	if !validEventIdentity(identity) {
		return "", ErrInvalidIdentity
	}
	if !validTemplateRef(ref) {
		return "", ErrTemplateSelection
	}
	hash := sha256.New()
	for _, value := range []string{
		"notification-dedup-v1", identity.TenantID, identity.RecipientID,
		identity.EventID, identity.EventType, ref.ID, string(ref.Channel),
	} {
		writeLengthPrefixed(hash, value)
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], ref.Version)
	_, _ = hash.Write(version[:])
	return "notification-v1-" + hex.EncodeToString(hash.Sum(nil)), nil
}

func writeLengthPrefixed(writer hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func validEventIdentity(identity EventIdentity) bool {
	return validIdentityPart(identity.TenantID) && validIdentityPart(identity.RecipientID) &&
		validIdentityPart(identity.EventID) && validIdentityPart(identity.EventType)
}

func validIdentityPart(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' {
			return false
		}
	}
	return true
}
