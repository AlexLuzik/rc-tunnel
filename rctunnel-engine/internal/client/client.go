// Package client implements the RC-Tunnel data-plane client (rctc).
//
// The client keeps one TLS
// control connection to the server, registers its proxies, and on each
// reqWorkConn dials a fresh work connection plus the local service, then pipes
// bytes between them.
package client

import (
	"crypto/tls"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"rctunnel-engine/internal/proto"
)

// Config holds client-side settings.
type Config struct {
	ControlAddr  string // server control addr, e.g. "host:7000"
	WorkConnAddr string // server work-conn addr, e.g. "host:7001"
	Token        string
	Grant        string // panel-signed authorization grant
	ClientID     string
	Proxies      []proto.ProxySpec
	TLS          *tls.Config
}

// Client runs the agent-side tunnel engine.
type Client struct {
	cfg   Config
	mu    sync.Mutex        // guards local/ptype/ctrl/grant
	local map[string]string // proxy name -> local addr
	ptype map[string]string // proxy name -> type
	grant string            // current authorization grant (updated on reload)
	ctrl  net.Conn          // current control connection (nil if disconnected)
	wmu   sync.Mutex        // serializes control-conn writes
}

// New builds a Client.
func New(cfg Config) *Client {
	c := &Client{cfg: cfg, grant: cfg.Grant}
	c.setProxies(cfg.Proxies)
	return c
}

func (c *Client) currentGrant() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.grant
}

func (c *Client) setProxies(proxies []proto.ProxySpec) {
	local := map[string]string{}
	ptype := map[string]string{}
	for _, p := range proxies {
		local[p.Name] = p.LocalAddr
		ptype[p.Name] = p.Type
	}
	c.mu.Lock()
	c.local, c.ptype = local, ptype
	c.mu.Unlock()
}

func (c *Client) writeMsg(m *proto.Msg) error {
	c.mu.Lock()
	conn := c.ctrl
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return proto.WriteMsg(conn, m)
}

// Reload swaps the proxy set (and its authorization grant) and re-syncs it to
// the server over the live control connection (graceful reload — existing
// proxies/connections survive).
func (c *Client) Reload(proxies []proto.ProxySpec, grant string) {
	c.setProxies(proxies)
	c.mu.Lock()
	c.grant = grant
	c.mu.Unlock()
	if err := c.writeMsg(&proto.Msg{Type: proto.TypeUpdate, Proxies: proxies, Grant: grant}); err != nil {
		log.Printf("rctc: reload failed: %v", err)
		return
	}
	log.Printf("rctc: reloaded %d proxies", len(proxies))
}

// Run connects and serves, reconnecting forever with jittered backoff.
func (c *Client) Run() {
	backoff := time.Second
	for {
		start := time.Now()
		if err := c.session(); err != nil {
			log.Printf("rctc: session ended: %v", err)
		}
		if time.Since(start) > 60*time.Second { // healthy session -> reset backoff
			backoff = time.Second
		}
		// full jitter: spread reconnects so a node restart doesn't trigger a
		// thundering herd of agents reconnecting in lockstep.
		d := backoff/2 + time.Duration(rand.Int63n(int64(backoff/2)+1))
		log.Printf("rctc: reconnecting in %s", d.Round(10*time.Millisecond))
		time.Sleep(d)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) dial(addr string) (net.Conn, error) {
	return tls.Dial("tcp", addr, c.cfg.TLS)
}

func (c *Client) session() error {
	conn, err := c.dial(c.cfg.ControlAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := proto.WriteMsg(conn, &proto.Msg{
		Type:     proto.TypeHello,
		Token:    c.cfg.Token,
		Grant:    c.currentGrant(),
		ClientID: c.cfg.ClientID,
		Proxies:  c.cfg.Proxies,
	}); err != nil {
		return err
	}
	resp, err := proto.ReadMsg(conn)
	if err != nil {
		return err
	}
	for _, st := range resp.Statuses {
		if st.OK {
			log.Printf("rctc: proxy %s ready", st.Name)
		} else {
			log.Printf("rctc: proxy %s rejected: %s", st.Name, st.Error)
		}
	}

	// expose this conn for heartbeats + reload, clear on exit
	c.mu.Lock()
	c.ctrl = conn
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.ctrl = nil; c.mu.Unlock() }()

	// heartbeat
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if c.writeMsg(&proto.Msg{Type: proto.TypePing}) != nil {
					return
				}
			}
		}
	}()

	for {
		m, err := proto.ReadMsg(conn)
		if err != nil {
			return err
		}
		if m.Type == proto.TypeReqWorkConn {
			go c.handleWork(m.ProxyName, m.ConnID)
		}
	}
}

// handleWork dials a work conn to the server and the local service, then pipes.
func (c *Client) handleWork(proxyName, connID string) {
	c.mu.Lock()
	localAddr := c.local[proxyName]
	ptyp := c.ptype[proxyName]
	c.mu.Unlock()
	if localAddr == "" {
		return
	}
	work, err := c.dial(c.cfg.WorkConnAddr)
	if err != nil {
		return
	}
	if err := proto.WriteMsg(work, &proto.Msg{Type: proto.TypeWorkConn, Token: c.cfg.Token, ConnID: connID}); err != nil {
		work.Close()
		return
	}
	if ptyp == "udp" {
		c.udpClient(work, localAddr)
		return
	}
	local, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
	if err != nil {
		work.Close()
		return
	}
	pipe(work, local)
}

// udpClient pumps framed datagrams between the work conn and per-source local
// UDP sockets. Each remote source gets its own dialed socket so replies route
// back correctly; idle sockets time out after 60s.
func (c *Client) udpClient(work net.Conn, localAddr string) {
	defer work.Close()
	var sessions sync.Map // src addr -> *net.UDPConn
	defer sessions.Range(func(_, v any) bool { v.(*net.UDPConn).Close(); return true })

	for {
		addr, data, err := proto.ReadDatagram(work)
		if err != nil {
			return
		}
		v, ok := sessions.Load(addr)
		if !ok {
			ua, err := net.ResolveUDPAddr("udp", localAddr)
			if err != nil {
				continue
			}
			lc, err := net.DialUDP("udp", nil, ua)
			if err != nil {
				continue
			}
			sessions.Store(addr, lc)
			go func(addr string, lc *net.UDPConn) {
				buf := make([]byte, 64*1024)
				for {
					_ = lc.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := lc.Read(buf)
					if err != nil {
						lc.Close()
						sessions.Delete(addr)
						return
					}
					if proto.WriteDatagram(work, addr, buf[:n]) != nil {
						lc.Close()
						sessions.Delete(addr)
						return
					}
				}
			}(addr, lc)
			v = lc
		}
		_, _ = v.(*net.UDPConn).Write(data)
	}
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}
