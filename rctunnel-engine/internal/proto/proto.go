// Package proto defines the RC-Tunnel control wire protocol.
//
// Control messages are length-prefixed JSON frames:
//
//	[4-byte big-endian length][JSON payload]
//
// They flow over a single TLS control connection between the client (rctc)
// and the server (rctd). Bulk tunnel data does NOT use this framing — once a
// work connection is paired it carries raw bytes via io.Copy.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// Message types.
const (
	TypeHello       = "hello"       // client -> server: auth + proxy registration
	TypeHelloResp   = "helloResp"   // server -> client: per-proxy accept/reject
	TypeUpdate      = "update"      // client -> server: re-sync proxy set (graceful reload)
	TypeReqWorkConn = "reqWorkConn" // server -> client: please dial a work conn for ConnID
	TypeWorkConn    = "workConn"    // client -> server (new conn): claim a pending ConnID
	TypePing        = "ping"        // client -> server: heartbeat
	TypePong        = "pong"        // server -> client: heartbeat ack
)

// ProxySpec describes one tunnel the client wants to expose.
type ProxySpec struct {
	Name          string   `json:"name"`                    // global unique name, e.g. "t42"
	Type          string   `json:"type"`                    // tcp | udp | http | https
	LocalAddr     string   `json:"localAddr"`               // client-side target, e.g. 127.0.0.1:22
	RemotePort    int      `json:"remotePort,omitempty"`    // tcp/udp: public port on the server
	Subdomain     string   `json:"subdomain,omitempty"`     // http/https: vhost subdomain label chain
	CustomDomains []string `json:"customDomains,omitempty"` // http/https: explicit FQDNs
}

// ProxyStatus is the server's verdict for one requested proxy.
type ProxyStatus struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Msg is the single envelope for every control message.
type Msg struct {
	Type      string        `json:"type"`
	Token     string        `json:"token,omitempty"`
	Grant     string        `json:"grant,omitempty"`
	ClientID  string        `json:"clientId,omitempty"`
	Version   string        `json:"version,omitempty"`
	Proxies   []ProxySpec   `json:"proxies,omitempty"`
	OK        bool          `json:"ok,omitempty"`
	Error     string        `json:"error,omitempty"`
	Statuses  []ProxyStatus `json:"statuses,omitempty"`
	ProxyName string        `json:"proxyName,omitempty"`
	ConnID    string        `json:"connId,omitempty"`
}

// maxFrame bounds a single control frame to guard against bad input.
const maxFrame = 1 << 20 // 1 MiB

// WriteMsg encodes m as a length-prefixed JSON frame.
func WriteMsg(w io.Writer, m *Msg) error {
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(payload) > maxFrame {
		return errors.New("control frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// WriteDatagram frames one UDP datagram over a (TCP/TLS) work connection:
//
//	[4-byte BE total][2-byte BE addrlen][addr][data]
//
// addr is the original UDP peer address so the far side can route replies.
func WriteDatagram(w io.Writer, addr string, data []byte) error {
	if len(addr) > 0xffff || 2+len(addr)+len(data) > maxFrame {
		return errors.New("datagram too large")
	}
	total := 2 + len(addr) + len(data)
	buf := make([]byte, 4+total)
	binary.BigEndian.PutUint32(buf[0:4], uint32(total))
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(addr)))
	copy(buf[6:], addr)
	copy(buf[6+len(addr):], data)
	_, err := w.Write(buf)
	return err
}

// ReadDatagram reads one framed UDP datagram.
func ReadDatagram(r io.Reader) (addr string, data []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return "", nil, err
	}
	total := binary.BigEndian.Uint32(hdr[:])
	if total < 2 || total > maxFrame {
		return "", nil, errors.New("invalid datagram length")
	}
	buf := make([]byte, total)
	if _, err = io.ReadFull(r, buf); err != nil {
		return "", nil, err
	}
	alen := int(binary.BigEndian.Uint16(buf[0:2]))
	if 2+alen > len(buf) {
		return "", nil, errors.New("invalid datagram addr length")
	}
	return string(buf[2 : 2+alen]), buf[2+alen:], nil
}

// ReadMsg reads one length-prefixed JSON frame.
func ReadMsg(r io.Reader) (*Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return nil, errors.New("invalid control frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var m Msg
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
