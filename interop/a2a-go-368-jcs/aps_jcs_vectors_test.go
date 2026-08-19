// Harness: run the APS RFC 8785 canonical-bytes vectors (corpus v2, 10 vectors)
// against the JCS canonicalizer in this package.
//
// Written by the Agent Authority Conformance lab. This file is the lab's own
// harness; it is dropped into a checkout of the candidate branch because
// jcsMarshal is unexported and can only be reached from inside the package.
// No source file from this repository is copied out.
//
// Two decode modes are run and are kept apart in every output:
//
//	primary_usenumber : json.Decoder with UseNumber, then sortObjectKeys(obj, true),
//	                    then jcsMarshal. This replicates canonicalPayload exactly,
//	                    which is the AgentCard signing path. Numbers arrive as
//	                    json.Number and reach canonicalNumber.
//	secondary_float64 : plain json.Unmarshal, then jcsMarshal. Numbers arrive as
//	                    float64 and reach canonicalFloat without passing through
//	                    canonicalNumber. This is not the path canonicalPayload takes.
//
// Each vector is compared on three independent things per mode: the canonical
// string, the lowercase hex of the canonical bytes, and the SHA-256 of those bytes.
// Every comparison is asserted, so a canonical-byte mismatch makes go test exit
// non-zero. The exit code is a mechanism, not a verdict.
//
// Set APS_VECTORS to the fixture path and APS_OUT to the directory that should
// receive results.json.
package a2acrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type apsVector struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	Input             json.RawMessage `json:"input"`
	Canonical         string          `json:"canonical"`
	CanonicalBytesHex string          `json:"canonical_bytes_hex"`
	CanonicalSHA256   string          `json:"canonical_sha256"`
}

type apsFixture struct {
	Version     string      `json:"version"`
	Spec        string      `json:"spec"`
	GeneratedAt string      `json:"generated_at"`
	Vectors     []apsVector `json:"vectors"`
}

type apsCheck struct {
	Vector string `json:"vector"`
	Mode   string `json:"mode"`

	CanonicalMatch bool `json:"canonical_match"`
	HexMatch       bool `json:"hex_match"`
	SHA256Match    bool `json:"sha256_match"`

	ExpectedCanonical string `json:"expected_canonical"`
	ActualCanonical   string `json:"actual_canonical"`
	ExpectedHex       string `json:"expected_canonical_bytes_hex"`
	ActualHex         string `json:"actual_canonical_bytes_hex"`
	ExpectedSHA256    string `json:"expected_canonical_sha256"`
	ActualSHA256      string `json:"actual_canonical_sha256"`

	FirstDiffOffset int `json:"first_diff_byte_offset"`

	// Which branch of canonicalNumber the top-level numeric token takes under the
	// primary path. Recorded, not judged.
	NumberBranch string `json:"number_branch,omitempty"`

	Error string `json:"error,omitempty"`
}

// firstDiff returns the index of the first differing byte, or -1 when equal.
func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// numberBranch reports which branch of canonicalNumber a top-level numeric token
// takes, by applying the same predicates canonicalNumber applies. Descriptive only.
func numberBranch(input []byte) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(input, &probe); err != nil {
		return ""
	}
	raw, ok := probe["value"]
	if !ok {
		return ""
	}
	s := strings.TrimSpace(string(raw))
	if len(s) == 0 || s[0] == '"' || s[0] == '{' || s[0] == '[' {
		return ""
	}
	if strings.ContainsAny(s, ".eE") {
		return "float (ContainsAny .eE -> ParseFloat -> canonicalFloat)"
	}
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return "integer, ParseInt FAILED -> verbatim token fallback"
	}
	return "integer, ParseInt ok -> FormatInt of the decimal text"
}

// primaryUseNumber replicates canonicalPayload's sequence exactly: decode with
// UseNumber, sortObjectKeys(obj, true), jcsMarshal.
func primaryUseNumber(input []byte) ([]byte, error) {
	var obj any
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	sortObjectKeys(obj, true)
	return jcsMarshal(obj)
}

// secondaryFloat64 reaches jcsMarshal with numbers already widened to float64.
func secondaryFloat64(input []byte) ([]byte, error) {
	var obj any
	if err := json.Unmarshal(input, &obj); err != nil {
		return nil, err
	}
	return jcsMarshal(obj)
}

func runMode(v apsVector, mode string, fn func([]byte) ([]byte, error)) apsCheck {
	c := apsCheck{
		Vector:            v.Name,
		Mode:              mode,
		ExpectedCanonical: v.Canonical,
		ExpectedHex:       v.CanonicalBytesHex,
		ExpectedSHA256:    v.CanonicalSHA256,
		FirstDiffOffset:   -1,
	}
	if mode == "primary_usenumber" {
		c.NumberBranch = numberBranch(v.Input)
	}
	got, err := fn(v.Input)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	sum := sha256.Sum256(got)
	c.ActualCanonical = string(got)
	c.ActualHex = hex.EncodeToString(got)
	c.ActualSHA256 = hex.EncodeToString(sum[:])

	// The three comparisons are independent and are reported independently.
	c.CanonicalMatch = c.ActualCanonical == c.ExpectedCanonical
	c.HexMatch = c.ActualHex == c.ExpectedHex
	c.SHA256Match = c.ActualSHA256 == c.ExpectedSHA256
	c.FirstDiffOffset = firstDiff(got, []byte(v.Canonical))
	return c
}

func TestAPSCanonicalBytesVectors(t *testing.T) {
	path := os.Getenv("APS_VECTORS")
	if path == "" {
		t.Fatal("APS_VECTORS is not set; point it at canonical-bytes-jcs-v2.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var fx apsFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatal("fixture carries no vectors")
	}
	t.Logf("fixture version %s, %d vectors, generated_at %s", fx.Version, len(fx.Vectors), fx.GeneratedAt)

	modes := []struct {
		name string
		fn   func([]byte) ([]byte, error)
	}{
		{"primary_usenumber", primaryUseNumber},
		{"secondary_float64", secondaryFloat64},
	}

	results := map[string][]apsCheck{}
	for _, m := range modes {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Logf("=== MODE %s ===", m.name)
			for _, v := range fx.Vectors {
				v := v
				t.Run(v.Name, func(t *testing.T) {
					c := runMode(v, m.name, m.fn)
					results[m.name] = append(results[m.name], c)
					if c.Error != "" {
						t.Errorf("%s: canonicalization error: %s", v.Name, c.Error)
						return
					}
					if c.NumberBranch != "" {
						t.Logf("number branch: %s", c.NumberBranch)
					}
					// Three independent assertions, so the exit code reflects any of them.
					if !c.CanonicalMatch {
						t.Errorf("canonical string differs\n expected: %s\n actual  : %s\n first differing byte offset: %d",
							c.ExpectedCanonical, c.ActualCanonical, c.FirstDiffOffset)
					}
					if !c.HexMatch {
						t.Errorf("canonical bytes hex differs\n expected: %s\n actual  : %s",
							c.ExpectedHex, c.ActualHex)
					}
					if !c.SHA256Match {
						t.Errorf("canonical sha256 differs\n expected: %s\n actual  : %s",
							c.ExpectedSHA256, c.ActualSHA256)
					}
				})
			}
		})
	}

	// Counts are kept per mode and are never pooled.
	for _, m := range modes {
		n := 0
		for _, c := range results[m.name] {
			if c.CanonicalMatch && c.HexMatch && c.SHA256Match {
				n++
			}
		}
		t.Logf("COUNT %s: %d of %d vectors produced byte-identical canonical output",
			m.name, n, len(fx.Vectors))
	}

	if out := os.Getenv("APS_OUT"); out != "" {
		body := map[string]any{
			"fixture":              filepath.Base(path),
			"fixture_version":      fx.Version,
			"fixture_generated_at": fx.GeneratedAt,
			"vector_count":         len(fx.Vectors),
			"primary_usenumber":    results["primary_usenumber"],
			"secondary_float64":    results["secondary_float64"],
		}
		enc, err := json.MarshalIndent(body, "", " ")
		if err != nil {
			t.Fatalf("encoding results: %v", err)
		}
		if err := os.WriteFile(filepath.Join(out, "results.json"), append(enc, '\n'), 0o644); err != nil {
			t.Fatalf("writing results: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", filepath.Join(out, "results.json"))
	}
}
