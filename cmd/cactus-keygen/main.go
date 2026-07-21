// cactus-keygen writes a fresh 32-byte cosigner seed file, or inspects
// an existing one. The seed is used by the cactus server to derive its
// cosigner private key via HKDF (see signer/signer.go).
//
// Three output modes exist, because the two sides of a mirroring
// relationship want the same key in different encodings:
//
//   - -pub emits a PEM block whose body is the raw public key, which is
//     what a CA quorum mirror's public_key_path expects.
//   - -vkey emits a c2sp.org/signed-note vkey string, which is what a
//     tlog-mirror's log list expects in order to recognise our log.
//   - -from-vkey converts the other direction, turning a mirror's vkey
//     into the PEM form our own config consumes.
package main

import (
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
)

func main() {
	out := flag.String("o", "ca-cosigner.seed", "seed file path (written when generating, read when -pub/-vkey)")
	force := flag.Bool("f", false, "overwrite an existing seed file when generating")
	pub := flag.Bool("pub", false, "print the PEM public key for the seed at -o instead of generating one")
	vkey := flag.Bool("vkey", false, "print the c2sp signed-note vkey for the seed at -o (needs -cosigner-id)")
	cosignerID := flag.String("cosigner-id", "", "trust anchor ID of the COSIGNER whose OID name labels the key, in relative dotted-decimal form (e.g. 44363.47.1.99)")
	fromVkey := flag.String("from-vkey", "", "convert a c2sp vkey string to a PEM public key on stdout")
	alg := flag.String("alg", "mldsa-44", "cosigner algorithm")
	flag.Parse()

	if *fromVkey != "" {
		if err := printPEMFromVkey(*fromVkey); err != nil {
			die("%v", err)
		}
		return
	}

	if *vkey {
		if err := printVkey(*out, *alg, *cosignerID); err != nil {
			die("%v", err)
		}
		return
	}

	if *pub {
		if err := printPublicKey(*out, *alg); err != nil {
			die("%v", err)
		}
		return
	}

	dir := filepath.Dir(*out)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			die("mkdir %q: %v", dir, err)
		}
	}

	if *force {
		_ = os.Remove(*out)
	}
	if err := signer.WriteSeed(*out); err != nil {
		die("write seed: %v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *out, signer.SeedSize)
}

// printPublicKey derives the cosigner key from the seed at seedPath and
// writes the raw public key as a PEM "PUBLIC KEY" block to stdout — the
// form the mirror/quorum config fields consume.
func printPublicKey(seedPath, algName string) error {
	alg, err := signer.ParseAlgorithm(algName)
	if err != nil {
		return err
	}
	seed, err := signer.LoadSeed(seedPath)
	if err != nil {
		return err
	}
	s, err := signer.FromSeed(alg, seed)
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: s.PublicKey()})
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cactus-keygen: "+format+"\n", args...)
	os.Exit(1)
}

// sigTypeMLDSA44 is the c2sp.org/signed-note signature type byte for
// timestamped ML-DSA-44 (sub)tree cosignatures. It prefixes the public
// key material inside a vkey.
const sigTypeMLDSA44 = 0x06

// printVkey derives the cosigner key from the seed and prints it as a
// c2sp.org/signed-note vkey:
//
//	<name>+<hex key ID>+<base64(signature type || public key)>
//
// The name is the OID name of the COSIGNER, not of the log. A cactus
// checkpoint's origin line is the log ID (<CA-ID>.0.<log number>) but
// its signature line is labelled with the cosigner name, which is the
// CA ID (§5.4). A verifier matches the key by that name, so a vkey
// generated under the log ID silently fails to match and the mirror
// rejects add-checkpoint with 403. Give the log origin to the consumer
// separately — sunlight's log list has an `origin` line for exactly
// this case.
func printVkey(seedPath, algName, cosignerID string) error {
	if cosignerID == "" {
		return fmt.Errorf("-vkey requires -cosigner-id")
	}
	alg, err := signer.ParseAlgorithm(algName)
	if err != nil {
		return err
	}
	// The c2sp.org/signed-note vkey material prefixes the key with the
	// signature-type byte, which below is fixed to the ML-DSA-44 value
	// (0x06). c2sp assigns no such byte to ML-DSA-65/87, so a vkey for
	// those would be mislabeled as ML-DSA-44. The whole mirror/witness
	// cosignature path is ML-DSA-44-only anyway, so reject the others.
	if alg != signer.AlgMLDSA44 {
		return fmt.Errorf("-vkey is only defined for mldsa-44 (c2sp.org/tlog-cosignature assigns no vkey type to %s)", algName)
	}
	seed, err := signer.LoadSeed(seedPath)
	if err != nil {
		return err
	}
	s, err := signer.FromSeed(alg, seed)
	if err != nil {
		return err
	}
	name := cert.OIDName(cert.TrustAnchorID(cosignerID))
	certAlg, err := certAlgFor(alg)
	if err != nil {
		return err
	}
	keyID, err := cert.CosignatureKeyID(name, certAlg, s.PublicKey())
	if err != nil {
		return err
	}
	material := append([]byte{sigTypeMLDSA44}, s.PublicKey()...)
	fmt.Printf("%s+%x+%s\n", name, keyID, base64.StdEncoding.EncodeToString(material))
	return nil
}

// printPEMFromVkey converts a c2sp vkey into the PEM public key form the
// ca_cosigner_quorum mirror config consumes, and verifies the embedded
// key ID along the way so that a mistyped vkey fails here rather than
// silently producing a cosigner whose signatures never match.
func printPEMFromVkey(vkey string) error {
	// Split on only the first two '+': the key material is standard
	// base64, whose alphabet includes '+', so splitting on every one of
	// them would shred it. The name and hex key ID cannot contain '+'.
	parts := strings.SplitN(strings.TrimSpace(vkey), "+", 3)
	if len(parts) != 3 {
		return fmt.Errorf("vkey has %d '+'-separated fields, want 3", len(parts))
	}
	name, gotID := parts[0], parts[1]
	material, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("vkey key material: %w", err)
	}
	if len(material) < 1 {
		return fmt.Errorf("vkey key material is empty")
	}
	if material[0] != sigTypeMLDSA44 {
		return fmt.Errorf("vkey is not an ML-DSA-44 cosignature key (signature type 0x%02x)", material[0])
	}
	pub := material[1:]
	keyID, err := cert.CosignatureKeyID(name, cert.AlgMLDSA44, pub)
	if err != nil {
		return err
	}
	if want := fmt.Sprintf("%x", keyID); want != gotID {
		return fmt.Errorf("vkey key ID %s does not match key ID %s recomputed from the name and key", gotID, want)
	}
	return pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: pub})
}

// certAlgFor maps a signer.Algorithm to the parallel cert enum. The two
// use the same numeric codepoints but are distinct types.
func certAlgFor(a signer.Algorithm) (cert.SignatureAlgorithm, error) {
	switch a {
	case signer.AlgMLDSA44:
		return cert.AlgMLDSA44, nil
	case signer.AlgMLDSA65:
		return cert.AlgMLDSA65, nil
	case signer.AlgMLDSA87:
		return cert.AlgMLDSA87, nil
	default:
		return cert.AlgUnknown, fmt.Errorf("no cert algorithm for signer algorithm %v", a)
	}
}
