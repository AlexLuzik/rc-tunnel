# RC-Tunnel data-plane protocol

The RC-Tunnel data-plane protocol spoken between the server (`rctd`) and the
client (`rctc`).

## Connections

1. **Control** (TLS, optionally mTLS): one long-lived connection per agent.
   Carries registration + heartbeats. Length-prefixed JSON frames
   (`[4-byte BE length][JSON]`), see `internal/proto`.
2. **Work connection** (TLS): the client dials it back on demand after a
   `reqWorkConn`, then sends a one-frame `workConn` handshake. What it carries
   depends on the proxy type:
   - **tcp / http / https** — one work conn per public connection, short-lived;
     after the handshake it carries **raw bytes** (no framing), bridged 1:1.
   - **udp** — one **persistent** work conn per proxy that multiplexes every
     remote source as **framed datagrams** (see *UDP* below).
3. **Vhost** (plain HTTP, behind Caddy which terminates TLS): the server reads
   the `Host` header, routes to the owning client, then bridges.
4. **Stats** (plain HTTP, localhost): `GET /api/stats` → `{proxy: {in,out}}`
   for the panel traffic poller.

## Why a client behind NAT / CGNAT / double-NAT works

The client always *dials out* — control, work connections, everything is
client-initiated. Outbound flows traverse any NAT. The server (public IP)
relays. No hole-punching needed for tcp/udp/http/https. P2P (direct
client↔client) is a separate future feature and would always keep a
relay fallback.

## Control flow

```
client --hello{token,grant,clientId,proxies[]}-->  server
client <--helloResp{ok,statuses[]}---------        server   (opens public listeners)
                         ... per public connection ...
client <--reqWorkConn{proxyName,connId}----        server   (a request arrived)
client --(new conn)workConn{token,connId}-->       server   (paired with pending conn)
   then: client pipes workConn <-> local service; server pipes workConn <-> public
client --ping-->  / <--pong--                      server   (heartbeat, 30s)
```

`hello`/`update` also carry a panel-signed **grant** (`internal/grant`) that
scopes which ports/hosts the identity may register; the server verifies it and
rejects out-of-scope proxies.

## Proxy types

| Type   | Public side                          | Status |
|--------|--------------------------------------|--------|
| tcp    | server listens on `remotePort`       | done   |
| udp    | server listens UDP on `remotePort`   | done   |
| http   | vhost routes by `Host`               | done   |
| https  | vhost (TLS terminated by Caddy)      | done (same path as http) |

## UDP

UDP is connectionless, so it can't use the per-connection raw-bridge model.
Instead each udp proxy keeps **one persistent work connection** that carries
**framed datagrams**, multiplexing all remote sources over it:

```
public UDP :remotePort        rctd (udpServe)            rctc (udpClient)        local udp
   peer ─datagram──────────────▶ read, frame ─work conn▶ read frame
                                  with src addr           dial/reuse a per-src ──▶ service
                                                          local UDP socket
   peer ◀──────────────WriteToUDP◀ frame, addr ◀work conn◀ frame reply ◀──────── service reply
```

- The server's public UDP socket tags every inbound datagram with its **source
  address** and writes it framed to the work conn. If the work conn drops, the
  server re-requests one (`reqWorkConn`) with backoff.
- The client maintains a **per-source** dialed local UDP socket (`src addr →
  socket`) so replies from the local service route back to the right peer; each
  reply is framed back with the same source address and the server does
  `WriteToUDP` to that peer.

### Datagram frame

Over the (TLS) work connection, each datagram is length-prefixed:

```
[4-byte BE total][2-byte BE addrlen][addr bytes][payload bytes]
total = 2 + addrlen + len(payload)
```

`addr` is the original UDP peer address (e.g. `1.2.3.4:5678`) so either side can
route the datagram. Implemented by `proto.WriteDatagram` / `proto.ReadDatagram`.

> Operational note: a udp tunnel needs its public `remotePort` open **for UDP**
> in the host firewall (Caddy does not front udp). The control + work connections
> still use TCP/TLS as usual.

## Build

`./build-rctunnel.sh` — builds `bin/rctd` and `bin/rctc` for linux/amd64,
static, stripped, in an ephemeral `golang` container (no host toolchain).
