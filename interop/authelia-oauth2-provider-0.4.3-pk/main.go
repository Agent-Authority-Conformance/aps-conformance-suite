// pk_harness: runs the lab candidate aeoess-presenter-key-possession (vectors.json) through
// authelia.com/provider/oauth2 v0.4.3 handler/rfc9449 DefaultStrategy.ValidateResourceAccess,
// the resource-server DPoP check in the provider version Authelia main 399547a pins.
//
// Harness choices (not Authelia code):
//   - Time. ValidateDPoPProof reads time.Now(). The signed vectors fix now = 1793750400.
//     The harness sets clock skew 0 and proof lifespan = (real now - vector now) + iat_window_s,
//     so the vector's acceptance window [now-300, now] maps onto Authelia's window. The future
//     check cannot be exercised this way, so PK-17 is reported not_run.
//   - Nonce store: a nonce is valid iff it equals the case's server_nonce. requireNonce is
//     server_nonce != null.
//   - Replay store: in memory, keyed on (jti, normalized htu) as storage.go asks, preloaded
//     with the case's seen_jti through one earlier CheckAndSet call each.
//   - boundJKT is token_claims.cnf.jkt, empty when the token has no cnf (Authelia returns
//     invalid_token for that, documented as caller misuse).
//   - Authority (scope) is outside RFC 9449 and outside Authelia's DPoP code. Not evaluated.
//   - Axis of a reject is read from the error hint (mapping in axisOf).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"

	"authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc9449"
)

type cfg struct{ lifespan time.Duration }

func (c cfg) GetDPoPAllowedJWSAlgorithms(context.Context) []string     { return []string{"EdDSA"} }
func (c cfg) GetDPoPClockSkew(context.Context) time.Duration            { return 0 }
func (c cfg) GetDPoPProofLifespan(context.Context) time.Duration        { return c.lifespan }
func (c cfg) GetDPoPNonceLifespan(context.Context) time.Duration        { return time.Hour }
func (c cfg) GetDPoPNonceStateless(context.Context) bool                { return false }
func (c cfg) GetGlobalSecret(context.Context) ([]byte, error)           { return make([]byte, 32), nil }
func (c cfg) GetRotatedGlobalSecrets(context.Context) ([][]byte, error) { return nil, nil }

type store struct {
	mu    sync.Mutex
	used  map[string]bool
	nonce string
}

func (s *store) CheckAndSetDPoPProofUsed(_ context.Context, jti, jkt, nonce, htm, htu string, exp time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := jti + "\x00" + htu
	if s.used[k] {
		return true, nil
	}
	s.used[k] = true
	return false, nil
}
func (s *store) CreateDPoPNonce(context.Context, string, time.Time) error { return nil }
func (s *store) IsDPoPNonceValid(_ context.Context, n string) (bool, error) {
	return s.nonce != "" && n == s.nonce, nil
}

type vcase struct {
	ID    string `json:"id"`
	Input struct {
		Request struct {
			Method      string     `json:"method"`
			URI         string     `json:"uri"`
			ServerNonce *string    `json:"server_nonce"`
			SeenJTI     [][]string `json:"seen_jti"`
		} `json:"request"`
		AccessToken string `json:"access_token"`
		TokenClaims struct {
			Cnf *struct {
				JKT string `json:"jkt"`
			} `json:"cnf"`
		} `json:"token_claims"`
		DPoP   string `json:"dpop"`
		Policy struct {
			IatWindow int `json:"iat_window_s"`
		} `json:"policy"`
	} `json:"input"`
}

type result struct {
	ID       string `json:"id"`
	Decision string `json:"decision"`
	Axis     string `json:"axis,omitempty"`
	Error    string `json:"error"`
}

func hintOf(err error) string {
	var re *oauth2.RFC6749Error
	if errors.As(err, &re) {
		return re.ErrorField + ": " + re.HintField
	}
	return err.Error()
}

// axisOf maps an Authelia error hint to the candidate's axis names.
func axisOf(h string) string {
	l := strings.ToLower(h)
	switch {
	case strings.Contains(l, "not bound to a dpop key"), strings.Contains(l, "'ath'"),
		strings.Contains(l, "does not match the key the access token is bound to"):
		return "key_binding"
	case strings.Contains(l, "'htm'"), strings.Contains(l, "'htu'"), strings.Contains(l, "'iat'"),
		strings.Contains(l, "nonce"), strings.Contains(l, "already been used"):
		return "request_binding"
	default:
		return "proof_signature"
	}
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var doc struct {
		Now   int64   `json:"now"`
		Cases []vcase `json:"cases"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	ctx := context.Background()
	out := []result{}
	for _, c := range doc.Cases {
		if c.ID == "PK-17" {
			out = append(out, result{ID: c.ID, Decision: "not_run", Error: "harness: future iat not exercisable under the time shift"})
			continue
		}
		vnow := time.Unix(doc.Now, 0)
		life := time.Since(vnow) + time.Duration(c.Input.Policy.IatWindow)*time.Second
		st := &store{used: map[string]bool{}}
		if c.Input.Request.ServerNonce != nil {
			st.nonce = *c.Input.Request.ServerNonce
		}
		s := rfc9449.NewDefaultStrategy(cfg{lifespan: life}, st)
		for _, sj := range c.Input.Request.SeenJTI {
			// preload: normalized htu of the seen entry
			_, _ = st.CheckAndSetDPoPProofUsed(ctx, sj[1], "", "", "", strings.TrimRight(sj[0], "/"), time.Now().Add(time.Hour))
		}
		r := httptest.NewRequest(c.Input.Request.Method, c.Input.Request.URI, nil)
		r.Header.Set("Authorization", "DPoP "+c.Input.AccessToken)
		r.Header.Set("DPoP", c.Input.DPoP)
		jkt := ""
		if c.Input.TokenClaims.Cnf != nil {
			jkt = c.Input.TokenClaims.Cnf.JKT
		}
		_, err := s.ValidateResourceAccess(ctx, r, c.Input.AccessToken, jkt, c.Input.Request.ServerNonce != nil)
		if err != nil {
			h := hintOf(err)
			out = append(out, result{ID: c.ID, Decision: "reject", Axis: axisOf(h), Error: h})
		} else {
			out = append(out, result{ID: c.ID, Decision: "accept"})
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	fmt.Fprintln(os.Stderr, "cases:", len(out))
}
