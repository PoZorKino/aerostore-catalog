// Package fetch does all outbound http: size-capped downloads with timeouts,
// and a dialer that refuses private/loopback addresses (submitted urls are
// untrusted, so the server must not be usable to probe its own network).
package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

var ErrTooBig = errors.New("file is larger than the allowed size")

// NewClient returns a client with dial/TLS/header timeouts. The overall
// deadline comes from the request context.
func NewClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !allowPrivate {
		d.Control = refusePrivate
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConnsPerHost:   4,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect to a non-https url")
			}
			return nil
		},
	}
}

func refusePrivate(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() || cgnat.Contains(ip) {
		return fmt.Errorf("refusing to connect to non-public address %s", host)
	}
	return nil
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func open(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aerostore-server/1 (+https://aerostore.dexx.moe)")
	// hash the bytes exactly as served; no transparent gzip
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("http %d from %s", resp.StatusCode, resp.Request.URL.Host)
	}
	return resp, nil
}

// Bytes downloads a small file fully into memory, failing past limit bytes.
func Bytes(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	resp, err := open(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > limit {
		return nil, ErrTooBig
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooBig
	}
	return b, nil
}

type Result struct {
	SHA256 string
	Size   int64
	Head   []byte // first bytes, for file type sniffing
}

// Hash streams url through sha256 without keeping it, failing past limit bytes.
func Hash(ctx context.Context, c *http.Client, url string, limit int64) (*Result, error) {
	resp, err := open(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > limit {
		return nil, ErrTooBig
	}
	h := sha256.New()
	head := &headWriter{max: 512}
	n, err := io.Copy(io.MultiWriter(h, head), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, ErrTooBig
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return nil, fmt.Errorf("short download: got %d of %d bytes", n, resp.ContentLength)
	}
	return &Result{SHA256: hex.EncodeToString(h.Sum(nil)), Size: n, Head: head.buf.Bytes()}, nil
}

type headWriter struct {
	buf bytes.Buffer
	max int
}

func (w *headWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// Kind guesses exe / msi / zip from magic bytes, "" if none match.
func Kind(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("MZ")):
		return "exe"
	case bytes.HasPrefix(head, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}):
		return "msi"
	case bytes.HasPrefix(head, []byte("PK\x03\x04")):
		return "zip"
	}
	return ""
}
