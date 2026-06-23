package grant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sign builds a grant the same way the panel does (rctunnel_panel/grant.py).
func sign(secret, cn string, exp int64, ports []int, hosts []string) string {
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = strconv.Itoa(p)
	}
	msg := strings.Join([]string{"v1", cn, strconv.FormatInt(exp, 10), strings.Join(ps, ","), strings.Join(hosts, ",")}, "|")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return msg + "|" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestVerifyValid(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g, err := Verify("s3cret", sign("s3cret", "agent.7", now.Unix()+3600, []int{2222, 8080}, []string{"News.Example.com"}), "agent.7", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !g.AllowPort(2222) || !g.AllowPort(8080) || g.AllowPort(9999) {
		t.Fatal("port scope wrong")
	}
	if !g.AllowHost("news.example.com") { // verifier lowercases
		t.Fatal("host scope wrong (case)")
	}
	if g.AllowHost("evil.example.com") {
		t.Fatal("unauthorized host allowed")
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := now.Unix() + 3600
	good := sign("s3cret", "agent.7", exp, []int{2222}, nil)

	cases := map[string]struct {
		secret, grant, cn string
		at                time.Time
	}{
		"bad signature (wrong secret)": {"s3cret", sign("WRONG", "agent.7", exp, []int{2222}, nil), "agent.7", now},
		"cn mismatch":                  {"s3cret", good, "agent.8", now},
		"expired":                      {"s3cret", sign("s3cret", "agent.7", now.Unix()-1, []int{2222}, nil), "agent.7", now},
		"tampered scope":               {"s3cret", strings.Replace(good, "2222", "3333", 1), "agent.7", now},
		"malformed (too few fields)":   {"s3cret", "v1|agent.7|x", "agent.7", now},
		"wrong version tag":            {"s3cret", strings.Replace(good, "v1|", "v2|", 1), "agent.7", now},
		"empty":                        {"s3cret", "", "agent.7", now},
	}
	for name, c := range cases {
		if _, err := Verify(c.secret, c.grant, c.cn, c.at); err == nil {
			t.Errorf("%s: expected rejection, got nil error", name)
		}
	}
}

func TestVerifyEmptyScope(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g, err := Verify("s", sign("s", "agent.1", now.Unix()+10, nil, nil), "agent.1", now)
	if err != nil {
		t.Fatalf("empty-scope grant should verify: %v", err)
	}
	if g.AllowPort(2222) || g.AllowHost("x.com") {
		t.Fatal("empty-scope grant must authorize nothing")
	}
}
