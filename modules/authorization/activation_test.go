package authorization

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

func signedEnvelope(t *testing.T, payloadType string, payload []byte, keys []*ecdsa.PrivateKey) ([]byte, []TrustedKey) {
	t.Helper()
	trust := []TrustedKey{}
	signatures := []map[string]string{}
	for i, key := range keys {
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		id := policyrelease.SHA256Digest(spki)
		trust = append(trust, TrustedKey{CustodianID: "custodian-" + string(rune('a'+i)), KeyID: id, NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", Purpose: "release-policy", SPKIDERBase64: base64.StdEncoding.EncodeToString(spki), Status: "active"})
		digest := sha256.Sum256(policyrelease.PAE(payloadType, payload))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		half := new(big.Int).Rsh(new(big.Int).Set(key.Curve.Params().N), 1)
		if s.Cmp(half) > 0 {
			s.Sub(key.Curve.Params().N, s)
		}
		der, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		signatures = append(signatures, map[string]string{"keyid": id, "sig": base64.StdEncoding.EncodeToString(der)})
	}
	data, _ := json.Marshal(map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": signatures})
	return data, trust
}

func TestRealDSSESignaturesThresholdCustodyAndContinuousValidity(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	first, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	second, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	envelope, trust := signedEnvelope(t, policyrelease.ActivationManifestPayloadType, []byte(`{"schema_version":"1.0.0"}`), []*ecdsa.PrivateKey{first, second})
	parsed, err := policyrelease.ParseDSSEEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, receipts, err := verifySignatures(parsed, trust, 2, true, now); err != nil || len(receipts) != 2 {
		t.Fatal("real two-custodian P256 signatures rejected")
	}
	for name, mutate := range map[string]func([]TrustedKey){"revoked": func(keys []TrustedKey) { keys[0].Status = "revoked" }, "wrong-purpose": func(keys []TrustedKey) { keys[0].Purpose = "recovery" }, "expired": func(keys []TrustedKey) { keys[0].NotAfter = now.Format(time.RFC3339) }, "future": func(keys []TrustedKey) { keys[0].NotBefore = now.Add(time.Second).Format(time.RFC3339) }, "custodian-alias": func(keys []TrustedKey) { keys[1].CustodianID = keys[0].CustodianID }, "spki-alias": func(keys []TrustedKey) { keys[1].SPKIDERBase64 = keys[0].SPKIDERBase64 }, "key-alias": func(keys []TrustedKey) { keys[1].KeyID = keys[0].KeyID }} {
		t.Run(name, func(t *testing.T) {
			keys := append([]TrustedKey(nil), trust...)
			mutate(keys)
			if _, _, err := verifySignatures(parsed, keys, 2, true, now); err != ErrDenied {
				t.Fatal("unsafe trust accepted")
			}
		})
	}
	changed := parsed
	changed.Payload = append(append([]byte(nil), parsed.Payload...), ' ')
	if _, _, err := verifySignatures(changed, trust, 2, true, now); err != ErrDenied {
		t.Fatal("payload mutation accepted")
	}
	changed = parsed
	changed.PayloadType = policyrelease.ReleaseAttestationPayloadType
	if _, _, err := verifySignatures(changed, trust, 2, true, now); err != ErrDenied {
		t.Fatal("cross-type signature accepted")
	}
	changed = parsed
	changed.Signatures = changed.Signatures[:1]
	if _, _, err := verifySignatures(changed, trust, 2, true, now); err != ErrDenied {
		t.Fatal("threshold weakened")
	}
}

func TestActivationRejectsProductionAndIncompleteAuthority(t *testing.T) {
	if _, err := VerifyActivation(ActivationInput{}); err != ErrDenied {
		t.Fatal("empty activation authority")
	}
	if _, err := VerifyActivation(ActivationInput{LocalDevelopment: true, Anchor: AnchorState{Binding: bindingFixture(), PolicyTimeHighWater: time.Now(), PolicyTimeRevision: 1}, Now: time.Now()}); err != ErrDenied {
		t.Fatal("missing archive/signatures/model accepted")
	}
	for _, mode := range []string{"", "commit_boundary", "unknown"} {
		binding := bindingFixture()
		binding.DisclosureMode = mode
		if validBinding(binding) {
			t.Fatal("unsupported disclosure mode")
		}
	}
}
