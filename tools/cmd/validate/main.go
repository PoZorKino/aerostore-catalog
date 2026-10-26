// validate checks catalog manifests against docs/api.md. Meant for PR CI:
//
//	go run ./server/cmd/validate catalog/manifests/your.id.json
//	go run ./server/cmd/validate -download catalog/manifests
//
// Exits 1 if any file is invalid. A <id>.sig next to a manifest is checked
// against keys.json and reported, but only fails with -require-sig (PRs can't
// be signed by contributors).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aerostore-catalog/tools/internal/fetch"
	"aerostore-catalog/tools/internal/manifest"
	"aerostore-catalog/tools/internal/signing"
)

func main() {
	download := flag.Bool("download", false, "also download install.url and check sha256 and size")
	keysFlag := flag.String("keys", "", "trusted keys.json (default: keys.json next to each manifest's folder)")
	requireSig := flag.Bool("require-sig", false, "fail unless every manifest has a valid .sig")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: validate [-download] [-require-sig] [-keys keys.json] <manifest.json | dir>...\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var files []string
	for _, arg := range flag.Args() {
		st, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if st.IsDir() {
			m, _ := filepath.Glob(filepath.Join(arg, "*.json"))
			sort.Strings(m)
			files = append(files, m...)
		} else {
			files = append(files, arg)
		}
	}

	client := fetch.NewClient(false)
	failed := 0
	keys := keyCache{flag: *keysFlag, m: map[string]keysResult{}}
	for _, f := range files {
		errs := check(f, *download, client)
		sigMsg, sigOK := checkSig(f, &keys)
		if !sigOK && *requireSig {
			errs = append(errs, sigMsg)
		}
		if len(errs) > 0 {
			failed++
			fmt.Printf("FAIL %s\n", f)
			for _, e := range errs {
				fmt.Printf("  - %s\n", e)
			}
			if !*requireSig {
				fmt.Printf("  sig: %s\n", sigMsg)
			}
		} else {
			fmt.Printf("ok   %s (%s)\n", f, sigMsg)
		}
	}
	fmt.Printf("%d checked, %d failed\n", len(files), failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func check(file string, download bool, client *http.Client) []string {
	data, err := os.ReadFile(file)
	if err != nil {
		return []string{err.Error()}
	}
	m, err := manifest.Parse(data, manifest.Options{})
	if err != nil {
		var me manifest.Errors
		if errors.As(err, &me) {
			return me
		}
		return []string{err.Error()}
	}
	if err := manifest.CheckFileName(file, m); err != nil {
		return []string{err.Error()}
	}
	if pretty, _ := manifest.Pretty(m); strings.ReplaceAll(string(data), "\r\n", "\n") != string(pretty) {
		// not fatal: the server rewrites files in this form on approve
		fmt.Printf("note %s: not in canonical form (2-space indent, api.md key order)\n", file)
	}
	if !download {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := fetch.Hash(ctx, client, m.Install.URL, 2<<30)
	if err != nil {
		return []string{"download: " + err.Error()}
	}
	var errs []string
	if res.SHA256 != m.Install.SHA256 {
		errs = append(errs, fmt.Sprintf("sha256 mismatch: manifest %s, file %s", m.Install.SHA256, res.SHA256))
	}
	if res.Size != m.Install.Size {
		errs = append(errs, fmt.Sprintf("size mismatch: manifest %d, file %d", m.Install.Size, res.Size))
	}
	return errs
}

type keysResult struct {
	kr  signing.Keyring
	err error
}

type keyCache struct {
	flag string
	m    map[string]keysResult
}

func (c *keyCache) get(manifestPath string) (signing.Keyring, string, error) {
	p := c.flag
	if p == "" {
		p = filepath.Join(filepath.Dir(filepath.Dir(manifestPath)), "keys.json")
	}
	r, ok := c.m[p]
	if !ok {
		r.kr, r.err = signing.LoadKeys(p)
		c.m[p] = r
	}
	return r.kr, p, r.err
}

// checkSig describes the manifest's signature state; ok means it verifies.
func checkSig(file string, keys *keyCache) (string, bool) {
	sig, err := signing.ReadSig(signing.SigPath(file))
	if errors.Is(err, signing.ErrNoSig) {
		return "not signed (the maintainer signs after merge)", false
	}
	if err != nil {
		return err.Error(), false
	}
	kr, kp, err := keys.get(file)
	if errors.Is(err, os.ErrNotExist) {
		return "has a .sig but " + kp + " is missing, can't verify it", false
	}
	if err != nil {
		return err.Error(), false
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err.Error(), false
	}
	if err := kr.Verify(data, sig); err != nil {
		return "signature does not verify (" + err.Error() + "), it gets re-signed after merge", false
	}
	return "signature ok (key " + sig.KeyID + ")", true
}
