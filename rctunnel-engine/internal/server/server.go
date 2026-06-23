// Package server implements the RC-Tunnel data-plane server (rctd).
//
// Architecture: a single
// TLS control connection per client carries registration + heartbeats; each
// public connection is bridged to the client via an on-demand "work
// connection" that the client dials back. Bulk data is raw io.Copy.
package server

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rctunnel-engine/internal/grant"
	"rctunnel-engine/internal/proto"
)

// Config holds server-side settings.
type Config struct {
	ControlAddr  string // e.g. ":7000" — clients connect here (TLS)
	WorkConnAddr string // e.g. ":7001" — clients dial work connections here (TLS)
	VhostAddr    string // e.g. "127.0.0.1:8090" — HTTP vhost (behind Caddy), plain
	StatsAddr    string // e.g. "127.0.0.1:7401" — stats JSON for the panel poller
	Token        string // shared auth token
	GrantSecret  string // if set, clients must present a valid panel-signed grant
	TLS          *tls.Config
}

type pairing struct {
	pub   net.Conn
	ready chan net.Conn
	proxy string
	owner string // CN allowed to claim this work conn
}

// tokenEqual compares auth tokens in constant time (avoids a timing oracle).
func tokenEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// maxConns bounds concurrent connection-handler goroutines across all listeners,
// so a flood can't exhaust memory/FDs. Generous: legit fleets stay far below it,
// and the host nofile ulimit is the same order of magnitude.
const maxConns = 60000

// certCN returns the verified mTLS client cert CN, or "" if none.
func certCN(c net.Conn) string {
	if tc, ok := c.(*tls.Conn); ok {
		if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
			return cs.PeerCertificates[0].Subject.CommonName
		}
	}
	return ""
}

type proxyRef struct {
	client *Client
	spec   proto.ProxySpec
}

// Server is the running rctd instance.
type Server struct {
	cfg    Config
	mu     sync.Mutex
	vhosts map[string]*proxyRef // lowercased host -> ref (http/https)
	tcp    map[int]*proxyRef    // remote port -> ref (for conflict detection)
	pend    sync.Map            // connID -> *pairing
	stats   sync.Map            // proxy name -> *counters
	clients map[string]*Client  // clientID -> live control connection (for reconnect eviction)
	connSem chan struct{}       // bounds concurrent connection handlers (DoS backstop)
}

// acquire reserves a connection slot; false if at capacity (caller should drop).
func (s *Server) acquire() bool {
	select {
	case s.connSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) release() { <-s.connSem }

type counters struct {
	in  int64
	out int64
}

// New builds a Server.
func New(cfg Config) *Server {
	return &Server{cfg: cfg, vhosts: map[string]*proxyRef{}, tcp: map[int]*proxyRef{},
		clients: map[string]*Client{}, connSem: make(chan struct{}, maxConns)}
}

// Run starts all listeners and blocks.
func (s *Server) Run() error {
	cl, err := tls.Listen("tcp", s.cfg.ControlAddr, s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("control listen: %w", err)
	}
	wl, err := tls.Listen("tcp", s.cfg.WorkConnAddr, s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("workconn listen: %w", err)
	}
	go s.acceptWork(wl)
	if s.cfg.VhostAddr != "" {
		vl, err := net.Listen("tcp", s.cfg.VhostAddr)
		if err != nil {
			return fmt.Errorf("vhost listen: %w", err)
		}
		go s.acceptVhost(vl)
	}
	if s.cfg.StatsAddr != "" {
		go s.serveStats()
	}
	log.Printf("rctd: control=%s work=%s vhost=%s stats=%s", s.cfg.ControlAddr, s.cfg.WorkConnAddr, s.cfg.VhostAddr, s.cfg.StatsAddr)
	for {
		c, err := cl.Accept()
		if err != nil {
			return err
		}
		if !s.acquire() {
			_ = c.Close()
			continue
		}
		go func(c net.Conn) { defer s.release(); s.handleControl(c) }(c)
	}
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// --- control connection ---

// regEntry is one registered proxy with its teardown closures and the set of
// its currently-active connections (so removing the proxy can drop them).
type regEntry struct {
	spec    proto.ProxySpec
	closers []func()
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
}

func (e *regEntry) track(c net.Conn) {
	e.mu.Lock()
	if e.conns == nil {
		e.conns = map[net.Conn]struct{}{}
	}
	e.conns[c] = struct{}{}
	e.mu.Unlock()
}

func (e *regEntry) untrack(c net.Conn) {
	e.mu.Lock()
	delete(e.conns, c)
	e.mu.Unlock()
}

func (e *regEntry) closeAll() {
	e.mu.Lock()
	for c := range e.conns {
		_ = c.Close()
	}
	e.conns = map[net.Conn]struct{}{}
	e.mu.Unlock()
}

// Client is one connected agent (one control connection).
type Client struct {
	s       *Server
	id      string
	cn      string // verified identity (== id in prod), used to bind work conns
	grant   *grant.Grant
	ctrl    net.Conn
	writeMu sync.Mutex
	regMu   sync.Mutex
	regs    map[string]*regEntry // proxyName -> registration
	done    chan struct{}
}

// specKey captures the server-relevant fields; if it changes, re-register.
func specKey(p proto.ProxySpec) string {
	return fmt.Sprintf("%s|%d|%s|%v", p.Type, p.RemotePort, p.Subdomain, p.CustomDomains)
}

func (s *Server) handleControl(raw net.Conn) {
	defer raw.Close()
	hello, err := proto.ReadMsg(raw)
	if err != nil || hello.Type != proto.TypeHello {
		return
	}
	if s.cfg.Token != "" && !tokenEqual(hello.Token, s.cfg.Token) {
		_ = proto.WriteMsg(raw, &proto.Msg{Type: proto.TypeHelloResp, Error: "bad token"})
		return
	}
	// Stable client identity: prefer the verified mTLS cert CN (one agent =
	// one identity), fall back to the hello ClientID, then random.
	cid := ""
	if tc, ok := raw.(*tls.Conn); ok {
		if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
			cid = cs.PeerCertificates[0].Subject.CommonName
		}
	}
	if cid == "" {
		cid = hello.ClientID
	}
	if cid == "" {
		cid = newID()
	}
	c := &Client{s: s, id: cid, cn: cid, ctrl: raw, regs: map[string]*regEntry{}, done: make(chan struct{})}
	// Authorization: a panel-signed grant scopes which ports/hosts this identity
	// may register. When GrantSecret is unset, ownership is not enforced (legacy).
	if s.cfg.GrantSecret != "" {
		g, err := grant.Verify(s.cfg.GrantSecret, hello.Grant, cid, time.Now())
		if err != nil {
			_ = proto.WriteMsg(raw, &proto.Msg{Type: proto.TypeHelloResp, Error: "grant: " + err.Error()})
			log.Printf("rctd: client %s rejected: %v", cid, err)
			return
		}
		c.grant = g
	}
	defer c.cleanup()
	// Evict any previous connection for this identity (reconnect/redeploy) so its
	// stale proxy/vhost registrations don't linger and serve foreign domains.
	s.mu.Lock()
	if old := s.clients[cid]; old != nil && old != c {
		_ = old.ctrl.Close()
	}
	s.clients[cid] = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.clients[cid] == c {
			delete(s.clients, cid)
		}
		s.mu.Unlock()
	}()

	statuses := c.applyUpdate(hello.Proxies)
	if err := proto.WriteMsg(raw, &proto.Msg{Type: proto.TypeHelloResp, OK: true, Statuses: statuses}); err != nil {
		return
	}
	log.Printf("rctd: client %s registered %d proxies", cid, len(c.regs))

	for {
		_ = raw.SetReadDeadline(time.Now().Add(90 * time.Second))
		m, err := proto.ReadMsg(raw)
		if err != nil {
			return
		}
		switch m.Type {
		case proto.TypePing:
			c.send(&proto.Msg{Type: proto.TypePong})
		case proto.TypeUpdate:
			if s.cfg.GrantSecret != "" {
				g, err := grant.Verify(s.cfg.GrantSecret, m.Grant, cid, time.Now())
				if err != nil {
					c.send(&proto.Msg{Type: proto.TypeHelloResp, Error: "grant: " + err.Error()})
					continue
				}
				c.grant = g
			}
			st := c.applyUpdate(m.Proxies)
			c.send(&proto.Msg{Type: proto.TypeHelloResp, OK: true, Statuses: st})
			log.Printf("rctd: client %s reloaded -> %d proxies", cid, len(c.regs))
		}
	}
}

// applyUpdate diffs the desired proxy set against the current registrations:
// unchanged proxies (and their live connections) are left untouched; removed
// ones are closed; new/changed ones are (re)registered. This is the graceful
// reload — toggling one tunnel never disturbs the others.
func (c *Client) applyUpdate(proxies []proto.ProxySpec) []proto.ProxyStatus {
	c.regMu.Lock()
	defer c.regMu.Unlock()
	desired := map[string]proto.ProxySpec{}
	for _, p := range proxies {
		desired[p.Name] = p
	}
	// remove proxies no longer desired, or whose spec changed
	for name, e := range c.regs {
		np, ok := desired[name]
		if !ok || specKey(np) != specKey(e.spec) {
			for _, cl := range e.closers {
				cl()
			}
			delete(c.regs, name)
		}
	}
	var statuses []proto.ProxyStatus
	for _, p := range proxies {
		if e, ok := c.regs[p.Name]; ok && specKey(e.spec) == specKey(p) {
			statuses = append(statuses, proto.ProxyStatus{Name: p.Name, OK: true}) // unchanged
			continue
		}
		statuses = append(statuses, c.register(p))
	}
	return statuses
}

func (c *Client) send(m *proto.Msg) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = proto.WriteMsg(c.ctrl, m)
}

// register opens the listeners/vhosts for one proxy and records an entry with
// teardown closures in c.regs. Caller holds c.regMu.
func (c *Client) register(p proto.ProxySpec) proto.ProxyStatus {
	// Ownership: only register ports/hosts this identity's grant authorizes.
	if c.grant != nil {
		switch p.Type {
		case "tcp", "udp":
			if !c.grant.AllowPort(p.RemotePort) {
				return proto.ProxyStatus{Name: p.Name, Error: fmt.Sprintf("port %d not authorized", p.RemotePort)}
			}
		case "http", "https":
			gh := append([]string{}, p.CustomDomains...)
			if p.Subdomain != "" {
				gh = append(gh, p.Subdomain)
			}
			for _, h := range gh {
				if !c.grant.AllowHost(h) {
					return proto.ProxyStatus{Name: p.Name, Error: "host not authorized: " + h}
				}
			}
		}
	}
	switch p.Type {
	case "tcp", "udp":
		if p.RemotePort <= 0 {
			return proto.ProxyStatus{Name: p.Name, Error: "remote port required"}
		}
		if p.Type == "udp" {
			ua, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", p.RemotePort))
			if err != nil {
				return proto.ProxyStatus{Name: p.Name, Error: err.Error()}
			}
			uc, err := net.ListenUDP("udp", ua)
			if err != nil {
				return proto.ProxyStatus{Name: p.Name, Error: fmt.Sprintf("udp port %d: %v", p.RemotePort, err)}
			}
			stop := make(chan struct{})
			go c.udpServe(uc, p.Name, stop)
			c.regs[p.Name] = &regEntry{spec: p, closers: []func(){
				func() { close(stop) }, func() { _ = uc.Close() },
			}}
			return proto.ProxyStatus{Name: p.Name, OK: true}
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.RemotePort))
		if err != nil {
			return proto.ProxyStatus{Name: p.Name, Error: fmt.Sprintf("port %d: %v", p.RemotePort, err)}
		}
		port := p.RemotePort
		c.s.mu.Lock()
		c.s.tcp[port] = &proxyRef{client: c, spec: p}
		c.s.mu.Unlock()
		entry := &regEntry{spec: p, conns: map[net.Conn]struct{}{}}
		entry.closers = []func(){
			func() { _ = ln.Close() },
			func() { c.s.mu.Lock(); delete(c.s.tcp, port); c.s.mu.Unlock() },
			entry.closeAll, // drop active connections when the proxy is removed
		}
		c.regs[p.Name] = entry
		go c.acceptPublic(ln, p, entry)
		return proto.ProxyStatus{Name: p.Name, OK: true}
	case "http", "https":
		hosts := append([]string{}, p.CustomDomains...)
		if p.Subdomain != "" {
			hosts = append(hosts, p.Subdomain)
		}
		if len(hosts) == 0 {
			return proto.ProxyStatus{Name: p.Name, Error: "no domains"}
		}
		ref := &proxyRef{client: c, spec: p}
		lowered := make([]string, 0, len(hosts))
		c.s.mu.Lock()
		// Reject if any host is already claimed by a DIFFERENT identity — prevents
		// cross-tenant vhost takeover (the same identity reconnecting may overwrite
		// its own entries). Check all before inserting any.
		for _, h := range hosts {
			lh := strings.ToLower(h)
			if ex, ok := c.s.vhosts[lh]; ok && ex.client != nil && ex.client.id != c.id {
				c.s.mu.Unlock()
				return proto.ProxyStatus{Name: p.Name, Error: "host already claimed: " + lh}
			}
			lowered = append(lowered, lh)
		}
		for _, lh := range lowered {
			c.s.vhosts[lh] = ref
		}
		c.s.mu.Unlock()
		c.regs[p.Name] = &regEntry{spec: p, closers: []func(){
			func() {
				c.s.mu.Lock()
				for _, lh := range lowered {
					if r, ok := c.s.vhosts[lh]; ok && r.client == c {
						delete(c.s.vhosts, lh)
					}
				}
				c.s.mu.Unlock()
			},
		}}
		return proto.ProxyStatus{Name: p.Name, OK: true}
	default:
		return proto.ProxyStatus{Name: p.Name, Error: "unknown type " + p.Type}
	}
}

func (c *Client) cleanup() {
	close(c.done)
	c.regMu.Lock()
	for _, e := range c.regs {
		for _, cl := range e.closers {
			cl()
		}
	}
	c.regs = map[string]*regEntry{}
	c.regMu.Unlock()
	log.Printf("rctd: client %s disconnected", c.id)
}

// acceptPublic handles inbound connections on a TCP proxy's public port.
func (c *Client) acceptPublic(ln net.Listener, p proto.ProxySpec, e *regEntry) {
	for {
		pub, err := ln.Accept()
		if err != nil {
			return
		}
		if !c.s.acquire() {
			_ = pub.Close()
			continue
		}
		go func(pub net.Conn) { defer c.s.release(); c.bridge(pub, p.Name, e) }(pub)
	}
}

// bridge requests a work conn from the client and pipes pub<->work. Both ends
// are tracked on the proxy's entry so a reload that removes the proxy drops them.
func (c *Client) bridge(pub net.Conn, proxyName string, e *regEntry) {
	connID := newID()
	pr := &pairing{pub: pub, ready: make(chan net.Conn, 1), proxy: proxyName, owner: c.cn}
	c.s.pend.Store(connID, pr)
	defer c.s.pend.Delete(connID)
	c.send(&proto.Msg{Type: proto.TypeReqWorkConn, ProxyName: proxyName, ConnID: connID})
	select {
	case work := <-pr.ready:
		e.track(pub)
		e.track(work)
		c.s.pipe(pub, work, proxyName)
		e.untrack(pub)
		e.untrack(work)
	case <-time.After(10 * time.Second):
		pub.Close()
	}
}

// udpServe bridges a UDP public socket to the client over a persistent work
// connection. A single uc reader writes to whatever work conn is current; a
// loop (re)establishes the work conn and pumps replies back.
func (c *Client) udpServe(uc *net.UDPConn, proxyName string, stop chan struct{}) {
	cnt := c.s.counters(proxyName)
	var mu sync.Mutex
	var cur net.Conn

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			w := cur
			mu.Unlock()
			if w == nil {
				continue
			}
			if proto.WriteDatagram(w, addr.String(), buf[:n]) == nil {
				atomic.AddInt64(&cnt.out, int64(n))
			}
		}
	}()

	backoff := 500 * time.Millisecond
	for {
		select {
		case <-c.done:
			return
		case <-stop:
			return
		default:
		}
		connID := newID()
		pr := &pairing{ready: make(chan net.Conn, 1), proxy: proxyName, owner: c.cn}
		c.s.pend.Store(connID, pr)
		c.send(&proto.Msg{Type: proto.TypeReqWorkConn, ProxyName: proxyName, ConnID: connID})
		var work net.Conn
		select {
		case work = <-pr.ready:
		case <-time.After(10 * time.Second):
		case <-c.done:
			c.s.pend.Delete(connID)
			return
		case <-stop:
			c.s.pend.Delete(connID)
			return
		}
		c.s.pend.Delete(connID)
		if work == nil {
			time.Sleep(backoff)
			if backoff < 5*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 500 * time.Millisecond
		mu.Lock()
		cur = work
		mu.Unlock()
		for {
			addr, data, err := proto.ReadDatagram(work)
			if err != nil {
				break
			}
			if ua, e := net.ResolveUDPAddr("udp", addr); e == nil {
				_, _ = uc.WriteToUDP(data, ua)
				atomic.AddInt64(&cnt.in, int64(len(data)))
			}
		}
		mu.Lock()
		cur = nil
		mu.Unlock()
		work.Close()
	}
}

// --- work connection intake ---

func (s *Server) acceptWork(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.acquire() {
			_ = c.Close()
			continue
		}
		go func(c net.Conn) { defer s.release(); s.handleWork(c) }(c)
	}
}

func (s *Server) handleWork(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	m, err := proto.ReadMsg(conn)
	if err != nil || m.Type != proto.TypeWorkConn {
		conn.Close()
		return
	}
	if s.cfg.Token != "" && !tokenEqual(m.Token, s.cfg.Token) {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	v, ok := s.pend.Load(m.ConnID)
	if !ok {
		conn.Close()
		return
	}
	pr := v.(*pairing)
	// Bind the work conn to the identity that owns the proxy: a leaked connID can't
	// be claimed by a different agent's connection. Enforced whenever the proxy has
	// an owner and the work conn presents a verified mTLS CN — independent of
	// GrantSecret, so isolation doesn't silently fail open without grants.
	if cn := certCN(conn); pr.owner != "" && cn != "" && cn != pr.owner {
		conn.Close()
		return
	}
	select {
	case pr.ready <- conn:
		// public side now owns piping
	default:
		conn.Close()
	}
}

// --- http vhost ---

func (s *Server) acceptVhost(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !s.acquire() {
			_ = c.Close()
			continue
		}
		go func(c net.Conn) { defer s.release(); s.handleVhost(c) }(c)
	}
}

func (s *Server) handleVhost(conn net.Conn) {
	// Bound how long a client may dribble request headers (slowloris) before we
	// have a parsed request; cleared once the request line+headers are in.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	host := strings.ToLower(req.Host)
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	s.mu.Lock()
	ref := s.vhosts[host]
	s.mu.Unlock()
	if ref == nil {
		writeStatus(conn, 404, "no such tunnel")
		conn.Close()
		return
	}
	connID := newID()
	pr := &pairing{pub: conn, ready: make(chan net.Conn, 1), proxy: ref.spec.Name, owner: ref.client.cn}
	s.pend.Store(connID, pr)
	defer s.pend.Delete(connID)
	ref.client.send(&proto.Msg{Type: proto.TypeReqWorkConn, ProxyName: ref.spec.Name, ConnID: connID})
	select {
	case work := <-pr.ready:
		// replay the request we already consumed, then pipe the rest
		if err := req.Write(work); err != nil {
			conn.Close()
			work.Close()
			return
		}
		s.pipeBuffered(conn, br, work, ref.spec.Name)
	case <-time.After(10 * time.Second):
		writeStatus(conn, 502, "tunnel timeout")
		conn.Close()
	}
}

func writeStatus(w io.Writer, code int, msg string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

// --- piping + stats ---

func (s *Server) counters(name string) *counters {
	v, _ := s.stats.LoadOrStore(name, &counters{})
	return v.(*counters)
}

// pipe bridges two raw connections, accounting bytes (in = client->public).
func (s *Server) pipe(pub, work net.Conn, proxy string) {
	cnt := s.counters(proxy)
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(pub, work); atomic.AddInt64(&cnt.in, n); done <- struct{}{} }()
	go func() { n, _ := io.Copy(work, pub); atomic.AddInt64(&cnt.out, n); done <- struct{}{} }()
	<-done
	pub.Close()
	work.Close()
	<-done
}

// pipeBuffered is like pipe but the public side has a bufio.Reader with
// possibly-buffered bytes (from reading the HTTP request line/headers).
func (s *Server) pipeBuffered(pub net.Conn, br *bufio.Reader, work net.Conn, proxy string) {
	cnt := s.counters(proxy)
	done := make(chan struct{}, 2)
	go func() { n, _ := io.Copy(pub, work); atomic.AddInt64(&cnt.in, n); done <- struct{}{} }()
	go func() { n, _ := io.Copy(work, br); atomic.AddInt64(&cnt.out, n); done <- struct{}{} }()
	<-done
	pub.Close()
	work.Close()
	<-done
}

// --- stats endpoint for the panel poller ---

func (s *Server) serveStats() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]map[string]int64{}
		s.stats.Range(func(k, v any) bool {
			c := v.(*counters)
			out[k.(string)] = map[string]int64{
				"in":  atomic.LoadInt64(&c.in),
				"out": atomic.LoadInt64(&c.out),
			}
			return true
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	_ = http.ListenAndServe(s.cfg.StatsAddr, mux)
}
