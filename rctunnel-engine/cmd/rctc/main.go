// Command rctc is the RC-Tunnel data-plane client (agent side).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"rctunnel-engine/internal/client"
	"rctunnel-engine/internal/proto"
)

// fileConfig is the on-disk JSON config the panel renders for the agent.
type fileConfig struct {
	ControlAddr  string            `json:"controlAddr"`
	WorkConnAddr string            `json:"workConnAddr"`
	Token        string            `json:"token"`
	Grant        string            `json:"grant"`
	ClientID     string            `json:"clientId"`
	CA           string            `json:"ca"`       // path to CA cert (verify server)
	Cert         string            `json:"cert"`     // path to client cert (mTLS)
	Key          string            `json:"key"`      // path to client key (mTLS)
	ServerName   string            `json:"serverName"`
	Insecure     bool              `json:"insecure"` // skip server verification (testing only)
	Proxies      []proto.ProxySpec `json:"proxies"`
}

func main() {
	cfgPath := flag.String("config", "", "path to JSON config")
	flag.Parse()
	if *cfgPath == "" {
		log.Fatal("rctc: -config required")
	}
	loadConfig := func() ([]proto.ProxySpec, string, bool) {
		raw, err := os.ReadFile(*cfgPath)
		if err != nil {
			log.Printf("rctc: reload read config: %v", err)
			return nil, "", false
		}
		var fc fileConfig
		if err := json.Unmarshal(raw, &fc); err != nil {
			log.Printf("rctc: reload parse config: %v", err)
			return nil, "", false
		}
		return fc.Proxies, fc.Grant, true
	}

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: fc.ServerName, InsecureSkipVerify: fc.Insecure}
	if fc.CA != "" {
		pem, err := os.ReadFile(fc.CA)
		if err != nil {
			log.Fatalf("read ca: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatal("rctc: bad CA pem")
		}
		tlsCfg.RootCAs = pool
	}
	if fc.Cert != "" {
		cert, err := tls.LoadX509KeyPair(fc.Cert, fc.Key)
		if err != nil {
			log.Fatalf("load client cert: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	c := client.New(client.Config{
		ControlAddr:  fc.ControlAddr,
		WorkConnAddr: fc.WorkConnAddr,
		Token:        fc.Token,
		Grant:        fc.Grant,
		ClientID:     fc.ClientID,
		Proxies:      fc.Proxies,
		TLS:          tlsCfg,
	})
	// SIGHUP -> graceful reload: re-read config, re-sync proxies without restart
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if proxies, grant, ok := loadConfig(); ok {
				log.Printf("rctc: SIGHUP — reloading %d proxies", len(proxies))
				c.Reload(proxies, grant)
			}
		}
	}()

	log.Printf("rctc: connecting to %s (%d proxies)", fc.ControlAddr, len(fc.Proxies))
	c.Run()
}
