package approvalapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCanonicalizeRFC8785Example(t *testing.T) {
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalizeSortsByUTF16(t *testing.T) {
	in := `{"\u20ac":1,"\r":2,"\ufb33":3,"1":4,"\ud83d\ude00":5,"\u0080":6,"\u00f6":7}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":2,\"1\":4,\"\u0080\":6,\"\u00f6\":7,\"\u20ac\":1,\"\U0001F600\":5,\"\ufb33\":3}"
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestCanonicalNumbers(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0", "-0": "0", "1": "1", "-1": "-1", "4.50": "4.5", "2e-3": "0.002",
		"1e20": "100000000000000000000", "1e21": "1e+21", "1e-6": "0.000001", "1e-7": "1e-7",
		"123456789012345678901": "123456789012345680000", "2592000": "2592000",
		"9007199254740991": "9007199254740991", "1.5e300": "1.5e+300", "-2.5e-9": "-2.5e-9",
	} {
		got, err := canonNumber(in)
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", in, got, err, want)
		}
	}
}

func TestCanonicalizeRefuses(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":1} 2`, `[1,`, `1e400`} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("%s: no error", in)
		}
	}
}

func sample() SubmitRequest {
	return SubmitRequest{
		IdempotencyKey: "req_1", Source: "warden", Kind: KindCredentialGrant, Tier: TierElevated,
		ApproverClass: "approve.credentials",
		Principal:     Principal{Sub: "agt_1", Kind: KindAgent, Act: []Actor{{Sub: "ses_1", Kind: KindSession}}},
		Requested:     Requested{Audience: "llm-gateway", Scopes: []string{"llm-gateway.decide"}, TTLSeconds: 2592000},
		Purpose:       "test", ExpiresAt: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
	}
}

func TestRequestDigest(t *testing.T) {
	s := sample()
	d, err := s.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// The canonical input, written out by hand: a second implementation must agree.
	canon := `{"principal":{"act":[{"kind":"session","sub":"ses_1"}],"kind":"agent","sub":"agt_1"},"requested":{"audience":"llm-gateway","constraints":{},"scopes":["llm-gateway.decide"],"ttl_seconds":2592000},"tier":"elevated"}`
	if want := "sha256:" + sha256Hex(canon); d != want {
		t.Fatalf("digest %s, want %s", d, want)
	}
	// nil and empty constraints digest the same; fields outside the three do not count.
	s.Requested.Constraints = map[string]any{}
	s.Purpose = "other"
	if d2, _ := s.Digest(); d2 != d {
		t.Fatal("digest changed with empty constraints or purpose")
	}
	s.Requested.Scopes = append(s.Requested.Scopes, "x")
	if d3, _ := s.Digest(); d3 == d {
		t.Fatal("digest did not change with scopes")
	}
}

func newKey(t *testing.T) (ed25519.PrivateKey, JWKS) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, JWKS{Keys: []JWK{PublicJWK("k1", pub)}}
}

func claims(now time.Time) DecisionClaims {
	s := sample()
	d, _ := s.Digest()
	return DecisionClaims{
		Iss: Issuer, Aud: "warden", Jti: "dec_1", Iat: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
		ApprovalID: "apr_1", RequestID: s.IdempotencyKey, RequestDigest: d, Outcome: OutcomeApproved,
		Tier: TierElevated, Decider: Actor{Sub: "agt_approver", Kind: KindAgent}, DecidedAt: now,
	}
}

func expect() Expect {
	s := sample()
	d, _ := s.Digest()
	return Expect{RequestID: s.IdempotencyKey, RequestDigest: d, Tier: s.Tier, Requested: s.Requested, Owner: "usr_owner"}
}

func TestDecisionRoundTrip(t *testing.T) {
	priv, keys := newKey(t)
	now := time.Now()
	tok, err := SignDecision(priv, "k1", claims(now))
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyDecision(tok, keys, "warden", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check(expect()); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionRefusals(t *testing.T) {
	priv, keys := newKey(t)
	other, _ := newKey(t)
	now := time.Now()
	good, _ := SignDecision(priv, "k1", claims(now))
	forged, _ := SignDecision(other, "k1", claims(now))
	unknownKid, _ := SignDecision(priv, "k2", claims(now))
	long := claims(now)
	long.Exp = now.Add(11 * time.Minute).Unix()
	tooLong, _ := SignDecision(priv, "k1", long)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"gatecrasher"}`)) + "." + parts[2]
	crit := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1","crit":["x"]}`)) + "." + parts[1] + "." + parts[2]
	cases := []struct {
		name, tok, aud string
		at             time.Time
		want           error
	}{
		{"forged", forged, "warden", now, ErrSignature},
		{"tampered", tampered, "warden", now, ErrSignature},
		{"wrong audience", good, "other", now, ErrMismatch},
		{"expired", good, "warden", now.Add(6 * time.Minute), ErrExpired},
		{"lifetime over ten minutes", tooLong, "warden", now, ErrMalformed},
		{"crit header", crit, "warden", now, ErrMalformed},
		{"two parts", "a.b", "warden", now, ErrMalformed},
	}
	for _, tc := range cases {
		if _, err := VerifyDecision(tc.tok, keys, tc.aud, tc.at); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := VerifyDecision(unknownKid, keys, "warden", now); err == nil {
		t.Error("unknown kid verified")
	}
}

func TestCheck(t *testing.T) {
	now := time.Now()
	mod := func(f func(*DecisionClaims)) DecisionClaims { c := claims(now); f(&c); return c }
	bad := map[string]DecisionClaims{
		"request id":    mod(func(c *DecisionClaims) { c.RequestID = "other" }),
		"digest":        mod(func(c *DecisionClaims) { c.RequestDigest = "sha256:00" }),
		"tier":          mod(func(c *DecisionClaims) { c.Tier = TierGround }),
		"widened scope": mod(func(c *DecisionClaims) { c.Narrowed = &Narrowed{Scopes: []string{"admin"}} }),
		"longer ttl":    mod(func(c *DecisionClaims) { c.Narrowed = &Narrowed{TTLSeconds: 2592001} }),
	}
	for name, c := range bad {
		if err := c.Check(expect()); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	ok := mod(func(c *DecisionClaims) {
		c.Narrowed = &Narrowed{Scopes: []string{"llm-gateway.decide"}, TTLSeconds: 3600}
	})
	if err := ok.Check(expect()); err != nil {
		t.Errorf("narrowing refused: %v", err)
	}

	crit := expect()
	crit.Tier = TierCritical
	byAgent := mod(func(c *DecisionClaims) { c.Tier = TierCritical })
	if err := byAgent.Check(crit); !errors.Is(err, ErrMismatch) {
		t.Errorf("critical by an agent: %v", err)
	}
	byOther := mod(func(c *DecisionClaims) { c.Tier = TierCritical; c.Decider = Actor{Sub: "usr_other", Kind: KindHuman} })
	if err := byOther.Check(crit); !errors.Is(err, ErrMismatch) {
		t.Errorf("critical by another human: %v", err)
	}
	byOwner := mod(func(c *DecisionClaims) { c.Tier = TierCritical; c.Decider = Actor{Sub: "usr_owner", Kind: KindHuman} })
	if err := byOwner.Check(crit); err != nil {
		t.Errorf("critical by the owner: %v", err)
	}
}

func TestSubmitRequestJSON(t *testing.T) {
	b, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"idempotency_key"`, `"approver_class"`, `"request_digest"`, `"expires_at"`, `"ttl_seconds"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s in %s", k, b)
		}
	}
}
