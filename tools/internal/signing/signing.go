// Package signing implements catalog signatures from docs/api.md: ed25519 over
// the exact bytes of <id>.json, stored as "<key id> <base64 sig>" in <id>.sig.
package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// PrivateKeyTag starts the one-line private key file: "<tag> <base64 32-byte seed>\n".
const PrivateKeyTag = "aerostore-ed25519-private"

const maxSigFile = 1 << 10

var (
	ErrNoSig      = errors.New("no .sig file")
	ErrUnknownKey = errors.New("signed with a key that is not in keys.json")
	ErrBadSig     = errors.New("signature does not match the manifest bytes")
	ErrNoKeys     = errors.New("no trusted keys (keys.json missing or empty)")
)

// KeyID is the first 16 hex chars of sha256(raw public key).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Key is one keys.json entry.
type Key struct {
	ID      string `json:"id"`
	Pub     string `json:"pub"`
	Comment string `json:"comment,omitempty"`
}

type KeysFile struct {
	Keys []Key `json:"keys"`
}

// Keyring maps key id to public key.
type Keyring map[string]ed25519.PublicKey

func ParseKeys(data []byte) (Keyring, error) {
	var kf KeysFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kf); err != nil {
		return nil, fmt.Errorf("keys.json: %w", err)
	}
	kr := Keyring{}
	for i, k := range kf.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.Pub)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keys.json: key %d: pub must be base64 of 32 bytes", i)
		}
		pub := ed25519.PublicKey(raw)
		if id := KeyID(pub); k.ID != id {
			return nil, fmt.Errorf("keys.json: key %d: id %q does not match its pub (want %s)", i, k.ID, id)
		}
		kr[k.ID] = pub
	}
	return kr, nil
}

// LoadKeys reads keys.json. A missing file gives an error matching os.ErrNotExist.
func LoadKeys(path string) (Keyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKeys(data)
}

// Sig is a parsed .sig file.
type Sig struct {
	KeyID string
	Sig   []byte
}

func (s Sig) Base64() string { return base64.StdEncoding.EncodeToString(s.Sig) }

// Format gives the .sig file content (one line, trailing LF).
func (s Sig) Format() []byte { return []byte(s.KeyID + " " + s.Base64() + "\n") }

func ParseSig(data []byte) (Sig, error) {
	f := strings.Fields(string(data))
	if len(f) != 2 {
		return Sig{}, errors.New("bad .sig file: want \"<key id> <base64 signature>\"")
	}
	if len(f[0]) != 16 {
		return Sig{}, errors.New("bad .sig file: key id must be 16 hex chars")
	}
	if _, err := hex.DecodeString(f[0]); err != nil {
		return Sig{}, errors.New("bad .sig file: key id must be 16 hex chars")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return Sig{}, errors.New("bad .sig file: signature must be base64 of 64 bytes")
	}
	return Sig{KeyID: strings.ToLower(f[0]), Sig: raw}, nil
}

// ReadSig reads a .sig file; a missing file gives ErrNoSig.
func ReadSig(path string) (Sig, error) {
	fh, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Sig{}, ErrNoSig
	}
	if err != nil {
		return Sig{}, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxSigFile+1))
	if err != nil {
		return Sig{}, err
	}
	if len(data) > maxSigFile {
		return Sig{}, errors.New("bad .sig file: too large")
	}
	return ParseSig(data)
}

// Verify checks sig over data against the keyring.
func (kr Keyring) Verify(data []byte, sig Sig) error {
	if len(kr) == 0 {
		return ErrNoKeys
	}
	pub, ok := kr[sig.KeyID]
	if !ok {
		return fmt.Errorf("%w (%s)", ErrUnknownKey, sig.KeyID)
	}
	if !ed25519.Verify(pub, data, sig.Sig) {
		return ErrBadSig
	}
	return nil
}

// SigPath is the .sig path for a manifest path (<id>.json -> <id>.sig).
func SigPath(manifestPath string) string {
	return strings.TrimSuffix(manifestPath, ".json") + ".sig"
}

func Sign(priv ed25519.PrivateKey, data []byte) Sig {
	return Sig{KeyID: KeyID(priv.Public().(ed25519.PublicKey)), Sig: ed25519.Sign(priv, data)}
}

func FormatPrivateKey(priv ed25519.PrivateKey) []byte {
	return []byte(PrivateKeyTag + " " + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
}

func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	f := strings.Fields(string(data))
	if len(f) != 2 || f[0] != PrivateKeyTag {
		return nil, fmt.Errorf("not an aerostore signing key (want \"%s <base64 seed>\")", PrivateKeyTag)
	}
	seed, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("bad signing key: seed must be base64 of 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}

// PubBase64 is the keys.json form of a public key.
func PubBase64(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }
