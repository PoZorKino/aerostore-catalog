// Package manifest holds the catalog manifest format from docs/api.md and its
// validator. The catalog loader, the submit endpoint and cmd/validate all use it.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Field order here is the key order of written manifests (matches api.md).
type Manifest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Publisher   string   `json:"publisher"`
	Summary     string   `json:"summary"`
	Description string   `json:"description,omitempty"`
	Category    string   `json:"category"`
	License     string   `json:"license"`
	Homepage    string   `json:"homepage,omitempty"`
	Source      string   `json:"source"`
	Icon        string   `json:"icon"`
	Screenshots []string `json:"screenshots"`
	Version     string   `json:"version"`
	Released    string   `json:"released,omitempty"`
	Install     Install  `json:"install"`
}

type Install struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	Format     string `json:"format,omitempty"`
	SilentArgs string `json:"silent_args,omitempty"`
	Detect     string `json:"detect,omitempty"`
	Archive    string `json:"archive,omitempty"`
	Exe        string `json:"exe,omitempty"`
}

var Categories = []string{
	"development", "graphics", "internet", "multimedia", "office",
	"system", "games", "utilities", "education", "security",
}

var (
	idRe     = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9-]+)+$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	spdxTok  = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)
)

// Options relaxes rules for submissions, where the server fills in the hash.
type Options struct {
	AllowMissingHash bool
}

// Errors is the full list of problems with one manifest.
type Errors []string

func (e Errors) Error() string { return strings.Join(e, "; ") }

// Parse decodes strictly (unknown keys are an error) and validates.
func Parse(data []byte, opt Options) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("bad json: trailing data after the manifest object")
	}
	m.Normalize()
	if err := Validate(&m, opt); err != nil {
		return &m, err
	}
	return &m, nil
}

// Normalize trims whitespace and makes nil slices empty so output is stable.
func (m *Manifest) Normalize() {
	for _, p := range []*string{&m.ID, &m.Name, &m.Publisher, &m.Summary, &m.Category,
		&m.License, &m.Homepage, &m.Source, &m.Icon, &m.Version, &m.Released,
		&m.Install.Type, &m.Install.URL, &m.Install.Format, &m.Install.SilentArgs,
		&m.Install.Detect, &m.Install.Archive, &m.Install.Exe} {
		*p = strings.TrimSpace(*p)
	}
	m.Description = strings.TrimSpace(strings.ReplaceAll(m.Description, "\r\n", "\n"))
	m.Install.SHA256 = strings.ToLower(strings.TrimSpace(m.Install.SHA256))
	shots := make([]string, 0, len(m.Screenshots))
	for _, s := range m.Screenshots {
		if s = strings.TrimSpace(s); s != "" {
			shots = append(shots, s)
		}
	}
	m.Screenshots = shots
}

func Validate(m *Manifest, opt Options) error {
	var errs Errors
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	switch {
	case m.ID == "":
		bad("id is required")
	case len(m.ID) > 64:
		bad("id is longer than 64 chars")
	case !idRe.MatchString(m.ID):
		bad("id %q must look like publisher.app: lowercase letters and digits, dots between parts, dashes allowed only after the first dot", m.ID)
	}
	text := func(field, v string, max int, required bool) {
		if v == "" {
			if required {
				bad("%s is required", field)
			}
			return
		}
		if !utf8.ValidString(v) {
			bad("%s is not valid utf-8", field)
		} else if n := utf8.RuneCountInString(v); n > max {
			bad("%s is %d chars, max is %d", field, n, max)
		}
	}
	text("name", m.Name, 60, true)
	text("publisher", m.Publisher, 60, true)
	text("summary", m.Summary, 100, true)
	text("description", m.Description, 4000, false)
	text("version", m.Version, 40, true)
	if strings.ContainsAny(m.Name+m.Summary+m.Publisher+m.Version, "\n\r\t") {
		bad("name, publisher, summary and version must be one line")
	}

	if !contains(Categories, m.Category) {
		bad("category %q is not one of: %s", m.Category, strings.Join(Categories, " "))
	}
	if m.License == "" {
		bad("license is required")
	} else if err := checkLicense(m.License); err != nil {
		bad("%v", err)
	}

	checkURL := func(field, v string, required bool) {
		if v == "" {
			if required {
				bad("%s is required", field)
			}
			return
		}
		if err := httpsURL(v); err != nil {
			bad("%s: %v", field, err)
		}
	}
	checkURL("homepage", m.Homepage, false)
	checkURL("source", m.Source, true)
	checkURL("icon", m.Icon, true)
	if len(m.Screenshots) > 6 {
		bad("at most 6 screenshots, got %d", len(m.Screenshots))
	}
	for i, s := range m.Screenshots {
		checkURL(fmt.Sprintf("screenshots[%d]", i), s, true)
	}
	if m.Released != "" {
		if _, err := time.Parse("2006-01-02", m.Released); err != nil || !dateRe.MatchString(m.Released) {
			bad("released must be YYYY-MM-DD")
		}
	}

	in := &m.Install
	checkURL("install.url", in.URL, true)
	if in.SHA256 == "" {
		if !opt.AllowMissingHash {
			bad("install.sha256 is required")
		}
	} else if !sha256Re.MatchString(in.SHA256) {
		bad("install.sha256 must be 64 lowercase hex chars")
	}
	if in.Size < 0 || (in.Size == 0 && !opt.AllowMissingHash) {
		bad("install.size must be the file size in bytes")
	}
	switch in.Type {
	case "installer":
		if in.Format != "exe" && in.Format != "msi" {
			bad("install.format must be exe or msi for an installer")
		}
		if in.Detect == "" {
			bad("install.detect is required for an installer (DisplayName prefix in the Uninstall key)")
		}
		text("install.detect", in.Detect, 120, false)
		text("install.silent_args", in.SilentArgs, 200, false)
		if in.Archive != "" || in.Exe != "" {
			bad("install.archive and install.exe are only for portable apps")
		}
	case "portable":
		switch in.Archive {
		case "zip":
			if err := relExePath(in.Exe); err != nil {
				bad("install.exe: %v", err)
			}
		case "exe":
			if in.Exe == "" || strings.ContainsAny(in.Exe, `/\:`) || !strings.HasSuffix(strings.ToLower(in.Exe), ".exe") {
				bad("install.exe must be a plain file name ending in .exe")
			}
		default:
			bad("install.archive must be zip or exe for a portable app")
		}
		if in.Format != "" || in.SilentArgs != "" || in.Detect != "" {
			bad("install.format, install.silent_args and install.detect are only for installers")
		}
	default:
		bad("install.type must be installer or portable")
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// CheckFileName enforces id == file name (without .json).
func CheckFileName(file string, m *Manifest) error {
	base := filepath.Base(file)
	if !strings.HasSuffix(base, ".json") {
		return fmt.Errorf("%s: manifest files must end in .json", base)
	}
	if want := strings.TrimSuffix(base, ".json"); want != m.ID {
		return fmt.Errorf("%s: id %q does not match the file name", base, m.ID)
	}
	return nil
}

// Pretty is the on-disk form: 2-space indent, trailing newline, no html escaping.
func Pretty(m *Manifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func httpsURL(v string) error {
	u, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("not a url")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must be an https:// url")
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("must have a host and no user info")
	}
	if len(v) > 2048 {
		return fmt.Errorf("url too long")
	}
	return nil
}

func relExePath(p string) error {
	if p == "" {
		return errors.New("required: path of the main exe inside the zip")
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(p, "/") || strings.Contains(p, ":") || path.Clean(p) != p ||
		strings.HasPrefix(p, "../") || p == ".." {
		return fmt.Errorf("%q must be a clean relative path inside the zip", p)
	}
	if !strings.HasSuffix(strings.ToLower(p), ".exe") {
		return fmt.Errorf("%q must end in .exe", p)
	}
	return nil
}

// checkLicense accepts an SPDX id or a simple AND/OR/WITH expression of free licenses.
func checkLicense(expr string) error {
	s := strings.NewReplacer("(", " ", ")", " ").Replace(expr)
	toks := strings.Fields(s)
	expectID := true
	afterWith := false
	for _, t := range toks {
		switch {
		case t == "AND" || t == "OR":
			if expectID {
				return fmt.Errorf("license %q is not a valid SPDX expression", expr)
			}
			expectID = true
		case t == "WITH":
			if expectID {
				return fmt.Errorf("license %q is not a valid SPDX expression", expr)
			}
			afterWith = true
		case afterWith:
			if !spdxTok.MatchString(t) {
				return fmt.Errorf("license %q has a bad exception id", expr)
			}
			afterWith = false
		default:
			if !expectID {
				return fmt.Errorf("license %q is not a valid SPDX expression", expr)
			}
			if !freeLicenses[t] {
				return fmt.Errorf("license %q is not a known OSI/FSF-approved SPDX id (use the exact SPDX id, e.g. GPL-3.0-or-later)", t)
			}
			expectID = false
		}
	}
	if expectID || afterWith {
		return fmt.Errorf("license %q is not a valid SPDX expression", expr)
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
