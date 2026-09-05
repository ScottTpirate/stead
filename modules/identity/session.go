// Package identity authenticates local development sessions. Authentication is
// context for central authorization and never grants access to a resource.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"time"
)

var ErrUnauthenticated = errors.New("authentication required")

type Principal struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return uuidV7.MatchString(id) }

func (principal Principal) Valid() bool {
	return ValidID(principal.ID) && (principal.Type == "user" || principal.Type == "agent" || principal.Type == "service_account")
}

// SessionRecord is returned only by the identity-owned repository. Tokens are
// stored as SHA-256 digests; no resource permission or administrator bypass is
// encoded in a session. A local session's actor must be a canonical active User.
type SessionRecord struct {
	ID                     string
	Principal              Principal
	InstanceID             string
	SecurityDomain         string
	Authority              string
	AuthenticationStrength string
	NetworkZone            string
	DeviceTrust            string
	Environment            string
	ClassificationCeilings map[string]string
	IssuedAt               time.Time
	ExpiresAt              time.Time
	Revision               uint64
	PrincipalRevision      uint64
	Active                 bool
	PrincipalActive        bool
}

type SessionRepository interface {
	LookupSession(context.Context, [sha256.Size]byte) (SessionRecord, error)
}

type LocalAuthenticator struct {
	repository SessionRepository
	instanceID string
	clock      func() time.Time
}

func NewLocalAuthenticator(repository SessionRepository, instanceID string, clock func() time.Time) (*LocalAuthenticator, error) {
	if repository == nil || !ValidID(instanceID) || clock == nil {
		return nil, ErrUnauthenticated
	}
	return &LocalAuthenticator{repository: repository, instanceID: instanceID, clock: clock}, nil
}

// Authenticated cannot be constructed from request fields. The repository is
// consulted on every request; there is no token or identity status cache.
type Authenticated struct{ record *SessionRecord }

func (session Authenticated) Principal() Principal {
	if session.record == nil {
		return Principal{}
	}
	return session.record.Principal
}
func (session Authenticated) SessionID() string {
	if session.record == nil {
		return ""
	}
	return session.record.ID
}
func (session Authenticated) ExpiresAt() time.Time {
	if session.record == nil {
		return time.Time{}
	}
	return session.record.ExpiresAt
}
func (session Authenticated) Context() SessionRecord {
	if session.record == nil {
		return SessionRecord{}
	}
	return cloneSession(*session.record)
}
func (session Authenticated) ValidAt(now time.Time) bool {
	return session.record != nil && validRecord(*session.record, session.record.InstanceID, now)
}

func (authenticator *LocalAuthenticator) Authenticate(ctx context.Context, token string) (Authenticated, error) {
	if authenticator == nil || ctx.Err() != nil || len(token) != 43 {
		return Authenticated{}, ErrUnauthenticated
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return Authenticated{}, ErrUnauthenticated
	}
	record, err := authenticator.repository.LookupSession(ctx, sha256.Sum256([]byte(token)))
	if err != nil || ctx.Err() != nil || !validRecord(record, authenticator.instanceID, authenticator.clock()) {
		return Authenticated{}, ErrUnauthenticated
	}
	record = cloneSession(record)
	return Authenticated{record: &record}, nil
}

func validRecord(record SessionRecord, instanceID string, now time.Time) bool {
	if !record.Principal.Valid() || record.Principal.Type != "user" || !record.Active || !record.PrincipalActive ||
		!ValidID(record.ID) || record.InstanceID != instanceID || !ValidID(instanceID) || record.SecurityDomain == "" ||
		record.Authority != "stead_local_identity" || record.AuthenticationStrength != "local_bootstrap" ||
		record.Environment != "local-development" || record.NetworkZone != "loopback" || record.DeviceTrust != "local" ||
		record.Revision == 0 || record.PrincipalRevision == 0 || record.IssuedAt.IsZero() || record.ExpiresAt.IsZero() ||
		now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) || !record.IssuedAt.Before(record.ExpiresAt) || len(record.ClassificationCeilings) == 0 {
		return false
	}
	for profile, ceiling := range record.ClassificationCeilings {
		if profile == "" || ceiling == "" {
			return false
		}
	}
	return true
}

func cloneSession(record SessionRecord) SessionRecord {
	copy := make(map[string]string, len(record.ClassificationCeilings))
	for profile, ceiling := range record.ClassificationCeilings {
		copy[profile] = ceiling
	}
	record.ClassificationCeilings = copy
	return record
}

// NewLocalToken supplies disposable development credentials to the trusted
// bootstrap command. Its caller persists only the digest and must expose the
// token only through local interactive setup; it is not an authorization grant.
func NewLocalToken() (string, [sha256.Size]byte, error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", [sha256.Size]byte{}, ErrUnauthenticated
	}
	token := base64.RawURLEncoding.EncodeToString(material[:])
	return token, sha256.Sum256([]byte(token)), nil
}
