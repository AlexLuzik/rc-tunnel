package e2e

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"rctunnel-engine/internal/client"
	"rctunnel-engine/internal/proto"
	"rctunnel-engine/internal/server"
)

// signGrant mirrors the panel's grant signer (HMAC-SHA256 over the canonical
// "v1|cn|exp|ports|hosts" string, base64url-no-pad signature appended).
func signGrant(secret, cn string, exp int64, ports []int, hosts []string) string {
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = strconv.Itoa(p)
	}
	msg := strings.Join([]string{"v1", cn, strconv.FormatInt(exp, 10), strings.Join(ps, ","), strings.Join(hosts, ",")}, "|")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return msg + "|" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestGrantEnforcement: with GrantSecret set, an agent may only register ports
// inside its signed grant; an out-of-scope port is rejected.
func TestGrantEnforcement(t *testing.T) {
	cert := selfSigned(t)
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	cliTLS := &tls.Config{InsecureSkipVerify: true}

	echo, err := net.Listen("tcp", "127.0.0.1:19222")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()

	srv := server.New(server.Config{ControlAddr: "127.0.0.1:27200", WorkConnAddr: "127.0.0.1:27201",
		Token: "x", GrantSecret: "topsecret", TLS: srvTLS})
	go func() { _ = srv.Run() }()
	if err := waitDial("127.0.0.1:27200", 3*time.Second); err != nil {
		t.Fatal(err)
	}

	// grant authorizes ONLY port 27290 for identity "gcli"
	g := signGrant("topsecret", "gcli", time.Now().Add(time.Hour).Unix(), []int{27290}, nil)
	cli := client.New(client.Config{ControlAddr: "127.0.0.1:27200", WorkConnAddr: "127.0.0.1:27201",
		Token: "x", Grant: g, ClientID: "gcli", TLS: cliTLS,
		Proxies: []proto.ProxySpec{
			{Name: "ok", Type: "tcp", LocalAddr: "127.0.0.1:19222", RemotePort: 27290},
			{Name: "bad", Type: "tcp", LocalAddr: "127.0.0.1:19222", RemotePort: 27291},
		}})
	go cli.Run()

	if err := waitDial("127.0.0.1:27290", 3*time.Second); err != nil {
		t.Fatal("authorized port 27290 never opened:", err)
	}
	if err := waitDial("127.0.0.1:27291", 800*time.Millisecond); err == nil {
		t.Fatal("unauthorized port 27291 should have been rejected by the grant")
	}
	t.Log("grant ownership enforced: authorized port up, out-of-scope port rejected")
}

// TestGrantRejectsForgery: a grant signed with the wrong secret is refused, so
// the agent gets no proxies at all (hello rejected).
func TestGrantRejectsForgery(t *testing.T) {
	cert := selfSigned(t)
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	cliTLS := &tls.Config{InsecureSkipVerify: true}

	srv := server.New(server.Config{ControlAddr: "127.0.0.1:27300", WorkConnAddr: "127.0.0.1:27301",
		Token: "x", GrantSecret: "realsecret", TLS: srvTLS})
	go func() { _ = srv.Run() }()
	if err := waitDial("127.0.0.1:27300", 3*time.Second); err != nil {
		t.Fatal(err)
	}

	forged := signGrant("WRONGsecret", "evil", time.Now().Add(time.Hour).Unix(), []int{27390}, nil)
	cli := client.New(client.Config{ControlAddr: "127.0.0.1:27300", WorkConnAddr: "127.0.0.1:27301",
		Token: "x", Grant: forged, ClientID: "evil", TLS: cliTLS,
		Proxies: []proto.ProxySpec{{Name: "x", Type: "tcp", LocalAddr: "127.0.0.1:19222", RemotePort: 27390}}})
	go cli.Run()

	if err := waitDial("127.0.0.1:27390", 1200*time.Millisecond); err == nil {
		t.Fatal("forged-grant client should be rejected; port 27390 must never open")
	}
	t.Log("forged grant rejected: no proxies registered")
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rctunnel-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func waitDial(addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", addr)
}

func TestReload(t *testing.T) {
	cert := selfSigned(t)
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	cliTLS := &tls.Config{InsecureSkipVerify: true}

	echo, err := net.Listen("tcp", "127.0.0.1:19122")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()

	srv := server.New(server.Config{ControlAddr: "127.0.0.1:27100", WorkConnAddr: "127.0.0.1:27101",
		Token: "x", TLS: srvTLS})
	go func() { _ = srv.Run() }()
	if err := waitDial("127.0.0.1:27100", 3*time.Second); err != nil {
		t.Fatal(err)
	}
	cli := client.New(client.Config{ControlAddr: "127.0.0.1:27100", WorkConnAddr: "127.0.0.1:27101",
		Token: "x", ClientID: "rl", TLS: cliTLS,
		Proxies: []proto.ProxySpec{{Name: "t1", Type: "tcp", LocalAddr: "127.0.0.1:19122", RemotePort: 27180}}})
	go cli.Run()
	if err := waitDial("127.0.0.1:27180", 3*time.Second); err != nil {
		t.Fatal("t1 never opened:", err)
	}

	a, err := net.Dial("tcp", "127.0.0.1:27180") // long-lived connection through t1
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	rt := func(c net.Conn, s string) string {
		c.Write([]byte(s))
		b := make([]byte, len(s))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.ReadFull(c, b)
		return string(b)
	}
	if rt(a, "one") != "one" {
		t.Fatal("t1 echo failed pre-reload")
	}

	// reload: ADD t2, keep t1
	cli.Reload([]proto.ProxySpec{
		{Name: "t1", Type: "tcp", LocalAddr: "127.0.0.1:19122", RemotePort: 27180},
		{Name: "t2", Type: "tcp", LocalAddr: "127.0.0.1:19122", RemotePort: 27181},
	}, "")
	if err := waitDial("127.0.0.1:27181", 3*time.Second); err != nil {
		t.Fatal("t2 never opened after reload:", err)
	}
	if rt(a, "two") != "two" { // the pre-existing connection must survive the reload
		t.Fatal("existing t1 connection was disrupted by reload")
	}

	// reload: REMOVE t1, keep t2
	cli.Reload([]proto.ProxySpec{{Name: "t2", Type: "tcp", LocalAddr: "127.0.0.1:19122", RemotePort: 27181}}, "")
	time.Sleep(300 * time.Millisecond)
	// the existing t1 connection must now be dropped (proxy removed = fully off)
	a.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := a.Read(make([]byte, 1)); e == nil {
		t.Fatal("existing t1 connection should be dropped when its proxy is removed")
	}
	if c, e := net.DialTimeout("tcp", "127.0.0.1:27180", 400*time.Millisecond); e == nil {
		c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		if _, e1 := c.Write([]byte("x")); e1 == nil {
			if _, e2 := c.Read(make([]byte, 1)); e2 == nil {
				t.Fatal("t1 should be closed after reload-remove")
			}
		}
		c.Close()
	}
	b, err := net.Dial("tcp", "127.0.0.1:27181")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if rt(b, "tee") != "tee" {
		t.Fatal("t2 broken after removing t1")
	}
	t.Log("graceful reload OK: existing conn survived add+remove")
}

func TestEndToEnd(t *testing.T) {
	cert := selfSigned(t)
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	cliTLS := &tls.Config{InsecureSkipVerify: true}

	// local "echo" service for the tcp tunnel
	echoLn, err := net.Listen("tcp", "127.0.0.1:19022")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()

	// local UDP "echo" service for the udp tunnel
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:19053")
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udpLn.ReadFrom(buf)
			if err != nil {
				return
			}
			udpLn.WriteTo(buf[:n], addr)
		}
	}()

	// local http service for the http tunnel
	httpLn, err := net.Listen("tcp", "127.0.0.1:19080")
	if err != nil {
		t.Fatal(err)
	}
	defer httpLn.Close()
	go http.Serve(httpLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.Host)
	}))

	srv := server.New(server.Config{
		ControlAddr:  "127.0.0.1:17900",
		WorkConnAddr: "127.0.0.1:17901",
		VhostAddr:    "127.0.0.1:18190",
		Token:        "secret",
		TLS:          srvTLS,
	})
	go func() { _ = srv.Run() }()
	if err := waitDial("127.0.0.1:17900", 3*time.Second); err != nil {
		t.Fatal(err)
	}

	cli := client.New(client.Config{
		ControlAddr:  "127.0.0.1:17900",
		WorkConnAddr: "127.0.0.1:17901",
		Token:        "secret",
		ClientID:     "test-agent",
		TLS:          cliTLS,
		Proxies: []proto.ProxySpec{
			{Name: "t1", Type: "tcp", LocalAddr: "127.0.0.1:19022", RemotePort: 17080},
			{Name: "t2", Type: "http", LocalAddr: "127.0.0.1:19080", Subdomain: "news.test.local"},
			{Name: "t3", Type: "udp", LocalAddr: "127.0.0.1:19053", RemotePort: 17053},
		},
	})
	go cli.Run()

	// tcp tunnel: public port should come up after registration
	if err := waitDial("127.0.0.1:17080", 3*time.Second); err != nil {
		t.Fatal("tcp public port never opened:", err)
	}
	t.Run("tcp", func(t *testing.T) {
		c, err := net.Dial("tcp", "127.0.0.1:17080")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		msg := "ping-through-tunnel"
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != msg {
			t.Fatalf("echo mismatch: got %q want %q", buf, msg)
		}
	})

	t.Run("http", func(t *testing.T) {
		c, err := net.Dial("tcp", "127.0.0.1:18190")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: news.test.local\r\nConnection: close\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		data, _ := io.ReadAll(bufio.NewReader(c))
		s := string(data)
		if !strings.Contains(s, "200 OK") || !strings.Contains(s, "hello from news.test.local") {
			t.Fatalf("unexpected http response:\n%s", s)
		}
	})

	t.Run("udp", func(t *testing.T) {
		ua, _ := net.ResolveUDPAddr("udp", "127.0.0.1:17053")
		c, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		msg := "udp-through-tunnel"
		// retry a couple times: udp work-conn establishes asynchronously
		var got string
		for i := 0; i < 20; i++ {
			c.Write([]byte(msg))
			c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 2048)
			n, err := c.Read(buf)
			if err == nil {
				got = string(buf[:n])
				break
			}
		}
		if got != msg {
			t.Fatalf("udp echo mismatch: got %q want %q", got, msg)
		}
	})

	// unknown host -> 404
	t.Run("http-unknown", func(t *testing.T) {
		c, err := net.Dial("tcp", "127.0.0.1:18190")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: nope.local\r\nConnection: close\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		data, _ := io.ReadAll(c)
		if !strings.Contains(string(data), "404") {
			t.Fatalf("expected 404, got:\n%s", data)
		}
	})
}
