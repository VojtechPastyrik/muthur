package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

func testKeySet(t *testing.T, n int) *HPKEKeySet {
	t.Helper()
	var pemData []byte
	for range n {
		p, err := GenerateHPKEKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		pemData = append(pemData, p...)
	}
	ks, err := ParseHPKEKeys(pemData)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestSealed_RoundTrip(t *testing.T) {
	ks := testKeySet(t, 1)
	pub := ks.Public()[0]

	body, opener, err := SealRequest(pub.Key, "/muthur/v1/ingest", "1700000000", "nonce", []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	pt, sealer, err := ks.OpenRequest(pub.KID, "/muthur/v1/ingest", "1700000000", "nonce", body)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "request" {
		t.Fatalf("plaintext %q", pt)
	}
	resp, err := sealer.Seal([]byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := opener.Open(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "response" {
		t.Fatalf("response %q", got)
	}
}

func TestSealed_BindsPathAndFreshness(t *testing.T) {
	ks := testKeySet(t, 1)
	pub := ks.Public()[0]
	body, _, err := SealRequest(pub.Key, "/muthur/v1/ingest", "1", "n", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ks.OpenRequest(pub.KID, "/muthur/v1/sign-csr", "1", "n", body); !errors.Is(err, ErrSealedMalformed) {
		t.Fatalf("path: %v", err)
	}
	if _, _, err := ks.OpenRequest(pub.KID, "/muthur/v1/ingest", "2", "n", body); !errors.Is(err, ErrSealedMalformed) {
		t.Fatalf("timestamp: %v", err)
	}
	if _, _, err := ks.OpenRequest(pub.KID, "/muthur/v1/ingest", "1", "m", body); !errors.Is(err, ErrSealedMalformed) {
		t.Fatalf("nonce: %v", err)
	}
	tampered := bytes.Clone(body)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := ks.OpenRequest(pub.KID, "/muthur/v1/ingest", "1", "n", tampered); !errors.Is(err, ErrSealedMalformed) {
		t.Fatalf("tamper: %v", err)
	}
}

func TestSealed_UnknownKeyAndRotation(t *testing.T) {
	ks := testKeySet(t, 2)
	pubs := ks.Public()
	if len(pubs) != 2 {
		t.Fatalf("want 2 keys, got %d", len(pubs))
	}
	// Both keys open, the first is the advertised one.
	for _, pub := range pubs {
		body, _, err := SealRequest(pub.Key, "/p", "1", "n", []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ks.OpenRequest(pub.KID, "/p", "1", "n", body); err != nil {
			t.Fatalf("kid %s: %v", pub.KID, err)
		}
	}
	if _, _, err := ks.OpenRequest("deadbeefdeadbeef", "/p", "1", "n", []byte{SealedVersion}); !errors.Is(err, ErrUnknownHPKEKey) {
		t.Fatalf("got %v", err)
	}
}

func TestParseHPKEKeys_RejectsNonX25519(t *testing.T) {
	if _, err := ParseHPKEKeys([]byte("garbage")); err == nil {
		t.Fatal("expected error for empty PEM")
	}
}

func TestPayloadSignature_RoundTrip(t *testing.T) {
	signer := newTestSigner(t)
	payload := []byte(`{"keys":[]}`)
	sig, err := signer.SignPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPayload(signer.CACert(), payload, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyPayload(signer.CACert(), []byte(`{"keys":[1]}`), sig); err == nil {
		t.Fatal("expected failure on altered payload")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSig, _ := SignPayload(other, payload)
	if err := VerifyPayload(signer.CACert(), payload, otherSig); err == nil {
		t.Fatal("expected failure on foreign signer")
	}
}
