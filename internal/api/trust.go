package api

import (
	"context"

	libauth "github.com/hollis-labs/libs/security/auth"
)

// WardenPrefix starts the principal id of every Warden-issued credential, so a Warden
// subject can never be mistaken for one of Gatecrasher's own identities.
const WardenPrefix = "warden:"

// WardenVerifier adapts a verifier of Warden-issued JWTs (aud=gatecrasher) for the
// approval routes: ids get WardenPrefix, and the kind is agent or service, never
// operator. The owner is matched by principal id, and settings refuse an owner
// principal with WardenPrefix, so a Warden credential is never the owner.
func WardenVerifier(v libauth.Verifier) libauth.Verifier { return wardenVerifier{v} }

type wardenVerifier struct{ v libauth.Verifier }

func (w wardenVerifier) Verify(ctx context.Context, token string) (libauth.Principal, error) {
	p, err := w.v.Verify(ctx, token)
	if err != nil {
		return libauth.Principal{}, err
	}
	p.ID = WardenPrefix + p.ID
	if p.Kind != libauth.KindAgent {
		p.Kind = libauth.KindService
	}
	return p, nil
}
