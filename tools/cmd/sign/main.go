// sign makes and checks catalog signatures (Signing section of docs/api.md).
// Run from the repo root:
//
//	go run ./server/cmd/sign keygen -out %USERPROFILE%\.aerostore\catalog-signing.key
//	go run ./server/cmd/sign manifests catalog/manifests
//	go run ./server/cmd/sign verify catalog/manifests
//
// The private key file is one line: "aerostore-ed25519-private <base64 32-byte seed>".
// Keep it offline; only the maintainer signs.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"

	"aerostore-catalog/tools/internal/manifest"
	"aerostore-catalog/tools/internal/signing"
)

const maxManifestFile = 256 << 10 // same limit as the server

func usage() {
	os.Stderr.WriteString(`usage:
  sign keygen -out <path>                     make a new signing key
  sign manifests [-key <path>] [-keys <keys.json>] <dir>
                                              sign manifests whose .sig is missing or invalid
  sign verify [-keys <keys.json>] <dir>       exit 1 unless every manifest has a valid .sig

-key defaults to $AEROSTORE_SIGNING_KEY, else %USERPROFILE%\.aerostore\catalog-signing.key.
-keys defaults to keys.json next to <dir> (catalog/keys.json for catalog/manifests).
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var code int
	switch os.Args[1] {
	case "keygen":
		code = keygen(os.Args[2:])
	case "manifests":
		code = signManifests(os.Args[2:])
	case "verify":
		code = verify(os.Args[2:])
	case "-h", "-help", "--help", "help":
		usage()
	default:
		usage()
		code = 2
	}
	os.Exit(code)
}

func die(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	return 1
}

func keygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "where to write the private key (must not exist)")
	fs.Parse(args)
	if *out == "" || fs.NArg() != 0 {
		usage()
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return die("keygen: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return die("keygen: %v", err)
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return die("keygen: %s already exists, not overwriting it", *out)
	}
	if err != nil {
		return die("keygen: %v", err)
	}
	if _, err := f.Write(signing.FormatPrivateKey(priv)); err != nil {
		f.Close()
		return die("keygen: %v", err)
	}
	if err := f.Close(); err != nil {
		return die("keygen: %v", err)
	}
	restrict(*out)

	id := signing.KeyID(pub)
	entry, _ := json.MarshalIndent(signing.Key{ID: id, Pub: signing.PubBase64(pub), Comment: "maintainer key"}, "    ", "  ")
	fmt.Printf("wrote private key to %s (keep it offline, back it up)\n\n", *out)
	fmt.Printf("public key: %s\nkey id:     %s\n\n", signing.PubBase64(pub), id)
	fmt.Printf("add this to catalog/keys.json \"keys\" (and to client/src/trusted_keys.h):\n    %s\n", entry)
	return 0
}

// restrict limits the key file to the current user. Best effort: 0600 does
// nothing useful on Windows, so drop inherited ACLs there.
func restrict(path string) {
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0o600)
		return
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		return
	}
	if out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", user+":F").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not restrict permissions on %s: %v %s\n", path, err, out)
	}
}

func defaultKeyPath() string {
	if p := os.Getenv("AEROSTORE_SIGNING_KEY"); p != "" {
		return p
	}
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".aerostore", "catalog-signing.key")
}

func manifestFiles(dir string) ([]string, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	sort.Strings(files)
	return files, err
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestFile+1))
	if err == nil && len(data) > maxManifestFile {
		err = errors.New("file too large")
	}
	return data, err
}

func validManifest(path string, data []byte) error {
	m, err := manifest.Parse(data, manifest.Options{})
	if err != nil {
		return err
	}
	return manifest.CheckFileName(path, m)
}

func loadKeysFlag(keysPath, dir string) (signing.Keyring, string, error) {
	if keysPath == "" {
		keysPath = filepath.Join(filepath.Dir(filepath.Clean(dir)), "keys.json")
	}
	kr, err := signing.LoadKeys(keysPath)
	return kr, keysPath, err
}

func signManifests(args []string) int {
	fs := flag.NewFlagSet("manifests", flag.ExitOnError)
	keyPath := fs.String("key", defaultKeyPath(), "private key file")
	keysPath := fs.String("keys", "", "trusted keys.json (default: keys.json next to <dir>)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
		return 2
	}
	dir := fs.Arg(0)
	priv, err := signing.LoadPrivateKey(*keyPath)
	if err != nil {
		return die("signing key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	ownID := signing.KeyID(pub)

	// existing sigs by any trusted key stay; ours always counts
	keys, kp, err := loadKeysFlag(*keysPath, dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return die("%v", err)
	}
	if keys == nil {
		keys = signing.Keyring{}
	}
	if _, ok := keys[ownID]; !ok {
		fmt.Printf("warning: key %s is not in %s, the server and app will ignore these signatures until it is\n", ownID, kp)
	}
	keys[ownID] = pub

	files, err := manifestFiles(dir)
	if err != nil {
		return die("%v", err)
	}
	signed, skipped, bad := 0, 0, 0
	for _, f := range files {
		data, err := readLimited(f)
		if err != nil {
			bad++
			fmt.Printf("SKIP  %s: %v\n", f, err)
			continue
		}
		sigPath := signing.SigPath(f)
		sig, err := signing.ReadSig(sigPath)
		if err == nil {
			err = keys.Verify(data, sig)
		}
		if err == nil {
			skipped++
			continue
		}
		why := err
		if err := validManifest(f, data); err != nil {
			bad++
			fmt.Printf("SKIP  %s: not signing an invalid manifest: %v\n", f, err)
			continue
		}
		if err := os.WriteFile(sigPath, signing.Sign(priv, data).Format(), 0o644); err != nil {
			return die("write %s: %v", sigPath, err)
		}
		signed++
		fmt.Printf("signed %s (was: %v)\n", f, why)
	}
	fmt.Printf("%d signed, %d already valid, %d skipped as invalid, key %s\n", signed, skipped, bad, ownID)
	if bad > 0 {
		return 1
	}
	return 0
}

func verify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	keysPath := fs.String("keys", "", "trusted keys.json (default: keys.json next to <dir>)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
		return 2
	}
	dir := fs.Arg(0)
	keys, kp, err := loadKeysFlag(*keysPath, dir)
	if err != nil {
		return die("%s: %v", kp, err)
	}
	files, err := manifestFiles(dir)
	if err != nil {
		return die("%v", err)
	}
	failed := 0
	for _, f := range files {
		data, err := readLimited(f)
		if err == nil {
			var sig signing.Sig
			if sig, err = signing.ReadSig(signing.SigPath(f)); err == nil {
				err = keys.Verify(data, sig)
			}
		}
		if err != nil {
			failed++
			fmt.Printf("UNSIGNED %s: %v\n", f, err)
		} else {
			fmt.Printf("ok       %s\n", f)
		}
	}
	// a .sig without its manifest is harmless but probably a leftover
	sigs, _ := filepath.Glob(filepath.Join(dir, "*.sig"))
	for _, s := range sigs {
		if _, err := os.Stat(s[:len(s)-len(".sig")] + ".json"); err != nil {
			fmt.Printf("note     %s has no manifest\n", s)
		}
	}
	fmt.Printf("%d checked, %d without a valid signature\n", len(files), failed)
	if failed > 0 {
		return 1
	}
	return 0
}
