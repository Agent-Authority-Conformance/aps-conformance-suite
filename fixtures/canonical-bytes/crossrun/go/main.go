// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
//
// Go runner for the RFC 8785 canonical-byte cross-run.
//
// Reports where this canonicalizer's bytes and SHA-256 agree with the pinned
// fixture. It is not a verdict on the implementation, and it is not APS
// conformance; it is a byte diff on ten cases.
//
// Canonicalizer under test: jcs.Canonicalize from
// github.com/aeoess/agent-passport-go, required at the published tag v0.5.0.
// There is deliberately no `replace` directive here: a replace pointing at a
// sibling checkout would make this report depend on a working tree that a
// person cloning this suite does not have.
//
// Every expected value is read from the fixture at run time. Nothing about the
// ten cases is transcribed into this file.
//
// Usage:
//   go run . [fixture-path]
// Default fixture: ../../canonical-bytes-jcs-v2.json
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/aeoess/agent-passport-go/jcs"
)

type vector struct {
	Name              string          `json:"name"`
	Input             json.RawMessage `json:"input"`
	CanonicalBytesHex string          `json:"canonical_bytes_hex"`
	CanonicalSha256   string          `json:"canonical_sha256"`
}

type fixtureFile struct {
	Vectors []vector `json:"vectors"`
}

type caseResult struct {
	Name                     string `json:"name"`
	ByteMatch                bool   `json:"byte_match"`
	Sha256Match              bool   `json:"sha256_match"`
	ActualBytesHex           string `json:"actual_bytes_hex"`
	ActualSha256             string `json:"actual_sha256"`
	FirstDivergentByteOffset *int   `json:"first_divergent_byte_offset"`
}

type summary struct {
	Total       int `json:"total"`
	ByteMatch   int `json:"byte_match"`
	Sha256Match int `json:"sha256_match"`
}

type report struct {
	Runner                string       `json:"runner"`
	Implementation        string       `json:"implementation"`
	ImplementationKind    string       `json:"implementation_kind"`
	ImplementationVersion string       `json:"implementation_version"`
	RuntimeVersion        string       `json:"runtime_version"`
	Fixture               string       `json:"fixture"`
	FixtureSha256         string       `json:"fixture_sha256"`
	Cases                 []caseResult `json:"cases"`
	Summary               summary      `json:"summary"`
}

// firstDivergentByteOffset returns the zero-based offset of the first differing
// byte. When one sequence is an exact prefix of the other there is no differing
// byte, so the answer is the length of the shorter one: the offset a reader
// would look at to see where the two stopped agreeing. Nil when equal.
func firstDivergentByteOffset(a, b []byte) *int {
	shared := len(a)
	if len(b) < shared {
		shared = len(b)
	}
	for i := 0; i < shared; i++ {
		if a[i] != b[i] {
			off := i
			return &off
		}
	}
	if len(a) == len(b) {
		return nil
	}
	return &shared
}

// depVersion reports the version of a dependency AS BUILT, read from the
// binary's own build info, rather than from go.mod. If a replace or a local
// override ever crept in, this reports what actually linked.
func depVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == path {
			if dep.Replace != nil {
				return fmt.Sprintf("%s (REPLACED by %s %s)", dep.Version, dep.Replace.Path, dep.Replace.Version)
			}
			return dep.Version
		}
	}
	return "unknown"
}

func main() {
	fixturePath := filepath.Join("..", "..", "canonical-bytes-jcs-v2.json")
	if len(os.Args) > 1 {
		fixturePath = os.Args[1]
	}
	abs, err := filepath.Abs(fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve fixture path:", err)
		os.Exit(1)
	}
	fixtureBytes, err := os.ReadFile(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read fixture:", err)
		os.Exit(1)
	}
	var parsed fixtureFile
	if err := json.Unmarshal(fixtureBytes, &parsed); err != nil {
		fmt.Fprintln(os.Stderr, "parse fixture:", err)
		os.Exit(1)
	}

	cases := make([]caseResult, 0, len(parsed.Vectors))
	var byteMatches, shaMatches int
	for _, v := range parsed.Vectors {
		// Decoding into interface{} gives every JSON number as a float64, which
		// is the binary64 value RFC 8785 serializes from, so the two
		// large-integer cases reach the canonicalizer already reduced to the
		// double the specification talks about.
		var input interface{}
		if err := json.Unmarshal(v.Input, &input); err != nil {
			fmt.Fprintf(os.Stderr, "decode input for %s: %v\n", v.Name, err)
			os.Exit(1)
		}
		canonical, err := jcs.Canonicalize(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "canonicalize %s: %v\n", v.Name, err)
			os.Exit(1)
		}
		actual := []byte(canonical)
		expected, err := hex.DecodeString(v.CanonicalBytesHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode expected hex for %s: %v\n", v.Name, err)
			os.Exit(1)
		}
		sum := sha256.Sum256(actual)
		actualSha := hex.EncodeToString(sum[:])
		byteMatch := string(actual) == string(expected)
		var offset *int
		if !byteMatch {
			offset = firstDivergentByteOffset(actual, expected)
		}
		if byteMatch {
			byteMatches++
		}
		if actualSha == v.CanonicalSha256 {
			shaMatches++
		}
		cases = append(cases, caseResult{
			Name:                     v.Name,
			ByteMatch:                byteMatch,
			Sha256Match:              actualSha == v.CanonicalSha256,
			ActualBytesHex:           hex.EncodeToString(actual),
			ActualSha256:             actualSha,
			FirstDivergentByteOffset: offset,
		})
	}

	fixtureSum := sha256.Sum256(fixtureBytes)
	out, err := json.MarshalIndent(report{
		Runner:                "go",
		Implementation:        "github.com/aeoess/agent-passport-go/jcs.Canonicalize",
		ImplementationKind:    "first_party",
		ImplementationVersion: depVersion("github.com/aeoess/agent-passport-go"),
		RuntimeVersion:        runtime.Version(),
		Fixture:               abs,
		FixtureSha256:         hex.EncodeToString(fixtureSum[:]),
		Cases:                 cases,
		Summary:               summary{Total: len(cases), ByteMatch: byteMatches, Sha256Match: shaMatches},
	}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode report:", err)
		os.Exit(1)
	}
	os.Stdout.Write(append(out, '\n'))
}
