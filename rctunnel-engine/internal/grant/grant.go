// Package grant verifies panel-issued authorization grants: a client (mTLS cert
// CN) may only register the tcp/udp ports and http/https hosts the panel signed
// for it. Format (HMAC-SHA256, base64url-no-pad), fields '|'-separated:
//
//	v1|<cn>|<exp-unix>|<port,port,...>|<host,host,...>|<sig>
//
// sig = base64url(HMAC(secret, "v1|<cn>|<exp>|<ports>|<hosts>")).
package grant

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Grant is a verified authorization scope for one client.
type Grant struct {
	CN    string
	Ports map[int]bool
	Hosts map[string]bool
}

// Verify checks the signature, the CN binding, and expiry, returning the
// allowed ports/hosts. secret must be non-empty.
func Verify(secret, s, cn string, now time.Time) (*Grant, error) {
	parts := strings.Split(s, "|")
	if len(parts) != 6 || parts[0] != "v1" {
		return nil, errors.New("bad grant format")
	}
	msg := strings.Join(parts[:5], "|")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[5])) {
		return nil, errors.New("bad grant signature")
	}
	if parts[1] != cn {
		return nil, errors.New("grant cn mismatch")
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || now.Unix() > exp {
		return nil, errors.New("grant expired")
	}
	g := &Grant{CN: parts[1], Ports: map[int]bool{}, Hosts: map[string]bool{}}
	if parts[3] != "" {
		for _, p := range strings.Split(parts[3], ",") {
			if n, e := strconv.Atoi(p); e == nil {
				g.Ports[n] = true
			}
		}
	}
	if parts[4] != "" {
		for _, h := range strings.Split(parts[4], ",") {
			g.Hosts[strings.ToLower(h)] = true
		}
	}
	return g, nil
}

// AllowPort reports whether a tcp/udp remote port is in scope.
func (g *Grant) AllowPort(p int) bool { return g.Ports[p] }

// AllowHost reports whether an http/https vhost is in scope.
func (g *Grant) AllowHost(h string) bool { return g.Hosts[strings.ToLower(h)] }
