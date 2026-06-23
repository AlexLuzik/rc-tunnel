// Command rctd is the RC-Tunnel data-plane server.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"log"
	"os"
	"sync"
	"time"

	"rctunnel-engine/internal/conf"
	"rctunnel-engine/internal/server"
)

// certReloader serves the server cert via tls.Config.GetCertificate, re-reading
// the PEM files from disk whenever their mtime changes. This lets a renewed
// server certificate take effect on new handshakes without restarting rctd.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	mtime             time.Time
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(r.certFile)
	if err == nil && (r.cert == nil || fi.ModTime().After(r.mtime)) {
		c, e := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		if e != nil {
			if r.cert != nil {
				return r.cert, nil // keep serving the last good cert
			}
			return nil, e
		}
		r.cert, r.mtime = &c, fi.ModTime()
	}
	if r.cert == nil {
		return nil, errors.New("no server certificate available")
	}
	return r.cert, nil
}

func main() {
	cfgPath := flag.String("config", "", "YAML config file (overrides flags)")
	control := flag.String("control", ":7000", "control listen address (TLS)")
	work := flag.String("work", ":7001", "work-connection listen address (TLS)")
	vhost := flag.String("vhost", "127.0.0.1:8090", "HTTP vhost listen address (plain, behind Caddy)")
	stats := flag.String("stats", "127.0.0.1:7401", "stats JSON listen address")
	token := flag.String("token", "", "shared auth token")
	grantSecret := flag.String("grant-secret", "", "HMAC secret for panel-signed authorization grants; if set, grants are enforced")
	certFile := flag.String("cert", "", "server TLS cert (PEM)")
	keyFile := flag.String("key", "", "server TLS key (PEM)")
	caFile := flag.String("ca", "", "client CA (PEM); if set, mTLS is required")
	revoked := flag.String("revoked", "", "file of revoked cert serials (one per line); hot-reloaded")
	flag.Parse()

	if *cfgPath != "" {
		data, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Fatalf("read config: %v", err)
		}
		m := conf.ParseFlat(data)
		set := func(dst *string, key string) {
			if v, ok := m[key]; ok {
				*dst = v
			}
		}
		set(control, "control")
		set(work, "work")
		set(vhost, "vhost")
		set(stats, "stats")
		set(token, "token")
		set(grantSecret, "grant_secret")
		set(certFile, "cert")
		set(keyFile, "key")
		set(caFile, "ca")
		set(revoked, "revoked")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if *certFile != "" {
		// validate at startup (fail fast), then serve via a hot-reloading
		// GetCertificate so a renewed server cert is picked up without a restart.
		if _, err := tls.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			log.Fatalf("load server cert: %v", err)
		}
		tlsCfg.GetCertificate = (&certReloader{certFile: *certFile, keyFile: *keyFile}).get
	} else {
		log.Fatal("rctd: -cert/-key are required")
	}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatalf("read ca: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatal("rctd: bad CA pem")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	// Without mTLS, client identity falls back to the agent-supplied hello.ClientID
	// (spoofable) and owner-binding/stat-attribution fail open. Refuse this in any
	// multi-tenant setup (grant enforcement on); warn for single-tenant token-only.
	if *caFile == "" {
		if *grantSecret != "" {
			log.Fatal("rctd: -grant-secret is set but -ca is missing — mTLS is required for tenant isolation")
		}
		log.Println("rctd: WARNING: -ca not set — mTLS disabled, no cross-tenant isolation (single-tenant only)")
	}

	srv := server.New(server.Config{
		ControlAddr:  *control,
		WorkConnAddr: *work,
		VhostAddr:    *vhost,
		StatsAddr:    *stats,
		Token:        *token,
		GrantSecret:  *grantSecret,
		RevokedFile:  *revoked,
		TLS:          tlsCfg,
	})
	log.Fatal(srv.Run())
}
