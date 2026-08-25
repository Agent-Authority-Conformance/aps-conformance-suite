// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// APS RFC 8785 canonical-bytes vectors run against the unexported jcsMarshal
// entry point. Placed in-package inside a checkout of the external branch.
// Two decode modes are run separately and are never pooled:
//
//   primary_usenumber  json.Decoder with UseNumber, then sortObjectKeys(obj, true),
//                      then jcsMarshal. Numbers arrive as json.Number.
//   secondary_float64  plain json.Unmarshal, then jcsMarshal. Numbers arrive as
//                      float64 and do not pass through canonicalNumber.
//
// Mode is selected by APS_MODE. Fixture path comes from APS_FIXTURE. Per-vector
// results are written as JSON to APS_OUT. Mismatches are recorded and the run
// continues; every vector is attempted under the selected mode.

package a2acrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
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
	Version string      `json:"version"`
	Vectors []apsVector `json:"vectors"`
}

type apsResult struct {
	Name              string `json:"name"`
	Mode              string `json:"mode"`
	Matched           bool   `json:"matched"`
	CanonicalMatch    bool   `json:"canonical_match"`
	HexMatch          bool   `json:"hex_match"`
	SHA256Match       bool   `json:"sha256_match"`
	ExpectedCanonical string `json:"expected_canonical"`
	ActualCanonical   string `json:"actual_canonical"`
	ExpectedHex       string `json:"expected_canonical_bytes_hex"`
	ActualHex         string `json:"actual_canonical_bytes_hex"`
	ExpectedSHA256    string `json:"expected_canonical_sha256"`
	ActualSHA256      string `json:"actual_canonical_sha256"`
	FirstDiffOffset   int    `json:"first_diff_offset"`
	Error             string `json:"error,omitempty"`
}

func apsFirstDiff(a, b string) int {
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

// apsCanonicalize runs one vector down one decode mode and returns the bytes
// jcsMarshal produced.
func apsCanonicalize(mode string, raw json.RawMessage) ([]byte, error) {
	var obj any
	if mode == "primary_usenumber" {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&obj); err != nil {
			return nil, err
		}
		sortObjectKeys(obj, true)
	} else {
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, err
		}
	}
	return jcsMarshal(obj)
}

func TestAPSCanonicalBytesVectors(t *testing.T) {
	mode := os.Getenv("APS_MODE")
	if mode != "primary_usenumber" && mode != "secondary_float64" {
		t.Fatalf("APS_MODE must be primary_usenumber or secondary_float64, got %q", mode)
	}
	fixturePath := os.Getenv("APS_FIXTURE")
	if fixturePath == "" {
		t.Fatalf("APS_FIXTURE is required")
	}
	blob, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var fx apsFixture
	if err := json.Unmarshal(blob, &fx); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	if len(fx.Vectors) == 0 {
		t.Fatalf("fixture carries no vectors")
	}

	results := make([]apsResult, 0, len(fx.Vectors))
	matched := 0

	for _, v := range fx.Vectors {
		r := apsResult{
			Name:              v.Name,
			Mode:              mode,
			ExpectedCanonical: v.Canonical,
			ExpectedHex:       v.CanonicalBytesHex,
			ExpectedSHA256:    v.CanonicalSHA256,
			FirstDiffOffset:   -1,
		}

		out, err := apsCanonicalize(mode, v.Input)
		if err != nil {
			// A vector jcsMarshal cannot accept at all is recorded and the run continues.
			r.Error = err.Error()
			results = append(results, r)
			t.Errorf("[%s] %s: jcsMarshal returned an error: %v", mode, v.Name, err)
			continue
		}

		sum := sha256.Sum256(out)
		r.ActualCanonical = string(out)
		r.ActualHex = hex.EncodeToString(out)
		r.ActualSHA256 = hex.EncodeToString(sum[:])

		// Three independent comparisons. All three are reported.
		r.CanonicalMatch = r.ActualCanonical == r.ExpectedCanonical
		r.HexMatch = r.ActualHex == r.ExpectedHex
		r.SHA256Match = r.ActualSHA256 == r.ExpectedSHA256
		r.Matched = r.CanonicalMatch && r.HexMatch && r.SHA256Match
		if !r.CanonicalMatch {
			r.FirstDiffOffset = apsFirstDiff(r.ExpectedCanonical, r.ActualCanonical)
		}

		if r.Matched {
			matched++
			t.Logf("[%s] %s: MATCH canonical=%s sha256=%s", mode, v.Name, r.ActualCanonical, r.ActualSHA256)
		} else {
			t.Errorf("[%s] %s: MISMATCH\n  expected canonical: %s\n  actual   canonical: %s\n"+
				"  expected sha256:    %s\n  actual   sha256:    %s\n"+
				"  canonical_match=%v hex_match=%v sha256_match=%v first_diff_offset=%d",
				mode, v.Name, r.ExpectedCanonical, r.ActualCanonical,
				r.ExpectedSHA256, r.ActualSHA256,
				r.CanonicalMatch, r.HexMatch, r.SHA256Match, r.FirstDiffOffset)
		}
		results = append(results, r)
	}

	t.Logf("[%s] %d of %d vectors produced byte-identical canonical output", mode, matched, len(fx.Vectors))

	if outPath := os.Getenv("APS_OUT"); outPath != "" {
		blob, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatalf("encoding results: %v", err)
		}
		if err := os.WriteFile(outPath, append(blob, '\n'), 0o644); err != nil {
			t.Fatalf("writing results: %v", err)
		}
	}
}
