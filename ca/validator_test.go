package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

func mkCSR(t *testing.T, dnsNames []string, ips []net.IP) *x509.CertificateRequest {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "x"},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(der)
	return csr
}

func TestValidatorAcceptsAuthorizedNames(t *testing.T) {
	v := NewValidator()
	csr := mkCSR(t, []string{"a.test", "b.test"}, nil)
	got, err := v.Validate(csr, OrderInput{
		AuthorizedDNSNames: []string{"a.test", "b.test"},
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !got.NotAfter.After(got.NotBefore) {
		t.Errorf("NotAfter <= NotBefore")
	}
}

func TestValidatorRejectsUnauthorizedNames(t *testing.T) {
	v := NewValidator()
	csr := mkCSR(t, []string{"a.test", "evil.example"}, nil)
	_, err := v.Validate(csr, OrderInput{AuthorizedDNSNames: []string{"a.test"}})
	if err == nil {
		t.Error("expected error for unauthorized SAN")
	}
}

func TestValidatorRejectsEmptyCSR(t *testing.T) {
	v := NewValidator()
	csr := mkCSR(t, nil, nil)
	_, err := v.Validate(csr, OrderInput{})
	if err == nil {
		t.Error("expected error for CSR with no SAN")
	}
}

func TestValidatorPinsValidityWindow(t *testing.T) {
	v := NewValidator()
	v.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	csr := mkCSR(t, []string{"a.test"}, nil)
	notAfter := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	got, err := v.Validate(csr, OrderInput{
		AuthorizedDNSNames: []string{"a.test"},
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           notAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, notAfter)
	}
}

func TestValidatorIPMustBeAuthorized(t *testing.T) {
	v := NewValidator()
	csr := mkCSR(t, nil, []net.IP{net.IPv4(1, 2, 3, 4)})
	_, err := v.Validate(csr, OrderInput{})
	if err == nil {
		t.Error("expected error for unauthorized IP SAN")
	}
	got, err := v.Validate(csr, OrderInput{
		AuthorizedIPs: []net.IP{net.IPv4(1, 2, 3, 4)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("nil result")
	}
}
