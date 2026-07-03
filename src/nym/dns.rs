// Copyright 2026 The Goblin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! DNS resolution THROUGH the mixnet, over DoT (DNS-over-TLS, RFC 7858).
//! `Tunnel::tcp_connect` takes a `SocketAddr`, so resolving the hostname is our
//! job (the old SOCKS5 network requester resolved at the exit for us) — and it
//! rides the tunnel so neither the query nor its answer ever touches the clear:
//! a clearnet lookup would leak exactly which relays/nodes Goblin contacts,
//! defeating the mixnet.
//!
//! WHY DoT (TCP+TLS), not the old UDP mix-dns: the previous path sent raw UDP
//! datagrams over the mixnet, and mixnet UDP LOSES packets — a lost datagram
//! stalled behind a multi-second timeout, and Phase-1 measurements showed
//! resolves taking ~10s (21 lost-datagram retries) which tipped relay connects
//! past the exit-condemnation grace and drove the 2-3 minute reselect loop. DoT
//! runs the DNS query over a TCP+TLS connection through the tunnel: TCP
//! RETRANSMITS, so there are no packet-loss stalls, and TLS ENCRYPTS the query
//! end to end, so not even the IPR exit can see (or forge) which host we asked
//! for. Reliable AND private AND authenticated — smolmix is a TCP tunnel and is
//! good at TCP. (The exit policy allows :853 — verified live by the
//! `probe_dns_ports` harness before shipping this; if a future exit blocks 853,
//! DoH on 443 is the drop-in fallback.)
//!
//! Wire codec: hickory-proto — already in the dependency graph via
//! nym-http-api-client, so no vendored encode/parse is needed. DoT framing is
//! the DNS message prefixed with its 2-byte big-endian length (RFC 1035 §4.2.2).
//! Answers land in a TTL-respecting in-memory cache and hosts are prewarmed at
//! startup, so a warm entry (not a fresh mixnet round trip) serves the common
//! case. IPv4-only, like the rest of the app (GRIM audit).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use log::{debug, warn};
use parking_lot::RwLock;
use smolmix::Tunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A DoT resolver: the IP:853 to dial through the tunnel and the SNI / cert name
/// its DoT endpoint presents (the query is validated against this hostname, so a
/// hostile exit that redirects the IP cannot MITM the lookup).
struct DotResolver {
	addr: SocketAddr,
	sni: &'static str,
}

/// DoT resolvers, RACED against each other (not primary/fallback) so a slow or
/// unlucky handshake to one never stalls behind it — whichever answers first
/// wins. Addressed BY IP (no bootstrap chicken-and-egg); the SNI is validated.
const DOT_RESOLVERS: [DotResolver; 2] = [
	DotResolver {
		addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853),
		sni: "cloudflare-dns.com",
	},
	DotResolver {
		addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 853),
		sni: "dns.quad9.net",
	},
];

/// A DoH resolver: the IP:443 to dial through the tunnel, its SNI/cert + Host
/// name, and the RFC 8484 query path. DoH is the FALLBACK for an exit whose
/// policy blocks DoT (:853) — 443 is guaranteed reachable (relays + HTTPS ride
/// it), so DNS never has to touch the clearnet.
struct DohResolver {
	ip: SocketAddr,
	sni: &'static str,
	host: &'static str,
	path: &'static str,
}

const DOH_RESOLVERS: [DohResolver; 2] = [
	DohResolver {
		ip: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
		sni: "cloudflare-dns.com",
		host: "cloudflare-dns.com",
		path: "/dns-query",
	},
	DohResolver {
		ip: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 443),
		sni: "dns.quad9.net",
		host: "dns.quad9.net",
		path: "/dns-query",
	},
];

/// Which in-tunnel DNS transport a lookup uses. NEVER clearnet.
#[derive(Clone, Copy)]
enum DnsMode {
	/// DoT — DNS-over-TLS on :853 (preferred; smallest overhead).
	Dot,
	/// DoH — DNS-over-HTTPS on :443 (fallback when an exit blocks :853).
	Doh,
}

/// Sticky: set once an exit is found to block DoT (:853), so we stop paying the
/// DoT timeout on every subsequent lookup and go straight to DoH (:443). Both
/// stay inside the tunnel — this only picks which in-tunnel transport to use.
static PREFER_DOH: AtomicBool = AtomicBool::new(false);

/// Per-query answer wait. DoT includes a TCP + TLS handshake over the mixnet
/// (a few seconds of deliberate per-hop delay), so allow more headroom than the
/// UDP path did; a round that exceeds this is retried rather than waited out.
const DOT_QUERY_TIMEOUT: Duration = Duration::from_secs(8);

/// Quick race-both-resolvers rounds before giving up. DoT is TCP-reliable within
/// a round, so two rounds is plenty (the second only matters if a whole
/// connection was dropped).
const DOT_ROUNDS: usize = 2;

/// DoH per-query wait (TCP + TLS + one HTTP round trip over the mixnet) and its
/// round count. Same reliability as DoT (TCP), a touch more per-request overhead
/// (HTTP framing), so the timeout is a shade more generous.
const DOH_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const DOH_ROUNDS: usize = 2;

/// TTL floor/ceiling for the cache: don't hammer resolvers for zero-TTL
/// records, don't trust a stale record for more than an hour.
const TTL_FLOOR_SECS: u32 = 60;
const TTL_CEILING_SECS: u32 = 3600;

/// TTL floor for KNOWN/stable hosts (relays, the name authority, the price API,
/// the DoT/DoH resolvers) — the ones we prewarm. Their addresses change rarely,
/// so we keep them cached at least 15 min (up to the 60-min ceiling) instead of
/// re-resolving every minute. Combined with serve-stale (below) this means a
/// dial to one of these NEVER blocks on a fresh mixnet DoT round trip.
const KNOWN_TTL_FLOOR_SECS: u32 = 900;

lazy_static! {
	/// host → (addresses, expiry).
	static ref CACHE: RwLock<HashMap<String, (Vec<Ipv4Addr>, Instant)>> =
		RwLock::new(HashMap::new());
	/// Hosts we treat as known/stable (populated by [`prewarm`]). Known hosts get
	/// the longer [`KNOWN_TTL_FLOOR_SECS`] floor AND serve-stale-while-revalidate.
	static ref KNOWN: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
	/// Hosts with a background revalidation in flight — single-flight guard so a
	/// burst of dials to a stale known host spawns exactly one refresh.
	static ref REFRESHING: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
}

/// Whether `host` is a known/stable host (has been prewarmed at least once).
fn is_known(host: &str) -> bool {
	KNOWN.read().contains(host)
}

/// Resolve `host` to a socket address for `tcp_connect`, entirely over the
/// mixnet via DoT. IP-literal hosts skip DNS; cached answers are honored until
/// their (clamped) TTL lapses. Each round RACES both resolvers concurrently and
/// takes the first valid answer; a round with no answer is retried. Returns
/// `None` only after every round fails.
pub async fn resolve(tunnel: &Tunnel, host: &str, port: u16) -> Option<SocketAddr> {
	// IP literals (v4 or v6) need no lookup at all.
	if let Ok(ip) = host.parse::<IpAddr>() {
		return Some(SocketAddr::new(ip, port));
	}
	match cache_hit(host) {
		// Fresh entry: serve it, no network at all.
		Some(CacheHit::Fresh(ip)) => return Some(SocketAddr::new(IpAddr::V4(ip), port)),
		// SERVE-STALE-WHILE-REVALIDATE for known/stable hosts: hand back the
		// last-known address immediately (so the dial never blocks on a cold DoT
		// round trip) and refresh it in the background. Unknown hosts fall
		// through to a blocking resolve, preserving correctness.
		Some(CacheHit::Stale(ip)) if is_known(host) => {
			spawn_revalidate(tunnel, host);
			return Some(SocketAddr::new(IpAddr::V4(ip), port));
		}
		_ => {}
	}
	resolve_cold(tunnel, host, port).await
}

/// The blocking DoT-then-DoH resolve, run when there is no usable cache entry.
/// Writes the cache on success.
async fn resolve_cold(tunnel: &Tunnel, host: &str, port: u16) -> Option<SocketAddr> {
	// If a previous lookup already learned this exit blocks DoT, go straight to
	// DoH — still entirely inside the tunnel.
	if PREFER_DOH.load(Ordering::Acquire) {
		return resolve_via(tunnel, host, port, DnsMode::Doh).await;
	}
	// DoT first; on total failure (exit likely blocks :853) fall back to DoH on
	// :443 — which is guaranteed reachable through the exit. There is NEVER a
	// clearnet fallback: both transports ride the mixnet.
	if let Some(addr) = resolve_via(tunnel, host, port, DnsMode::Dot).await {
		return Some(addr);
	}
	if !PREFER_DOH.swap(true, Ordering::AcqRel) {
		warn!("dns: DoT (:853) unavailable through this exit; using DoH (:443) over the tunnel");
	}
	resolve_via(tunnel, host, port, DnsMode::Doh).await
}

/// Kick off a background refresh of a stale known host through the current
/// tunnel, at most one in flight per host.
fn spawn_revalidate(tunnel: &Tunnel, host: &str) {
	let host = host.to_string();
	// Single-flight: skip if a refresh for this host is already running.
	if !REFRESHING.write().insert(host.clone()) {
		return;
	}
	let tunnel = tunnel.clone();
	tokio::spawn(async move {
		// Port is irrelevant here — only the host-keyed cache is refreshed.
		let _ = resolve_cold(&tunnel, &host, 0).await;
		REFRESHING.write().remove(&host);
	});
}

/// Run the round loop for one in-tunnel DNS transport, writing the cache on the
/// first valid answer. Shared by DoT / DoH.
async fn resolve_via(tunnel: &Tunnel, host: &str, port: u16, mode: DnsMode) -> Option<SocketAddr> {
	let (proto, rounds) = match mode {
		DnsMode::Dot => ("dot-dns", DOT_ROUNDS),
		DnsMode::Doh => ("doh-dns", DOH_ROUNDS),
	};
	let start = Instant::now();
	for round in 0..rounds {
		let answer = match mode {
			DnsMode::Dot => race_dot(tunnel, host).await,
			DnsMode::Doh => race_doh(tunnel, host).await,
		};
		if let Some((resolver, ips, ttl)) = answer {
			// Known/stable hosts get the longer floor so they stay cached 15-60
			// min; everything else keeps the tight 60s..1h window.
			let floor = if is_known(host) {
				KNOWN_TTL_FLOOR_SECS
			} else {
				TTL_FLOOR_SECS
			};
			let ttl = ttl.clamp(floor, TTL_CEILING_SECS);
			debug!(
				"{proto}: resolved {host} -> {} in {}ms (via {resolver}, round {}/{rounds}, \
				 ttl {ttl}s, {} record(s))",
				ips[0],
				start.elapsed().as_millis(),
				round + 1,
				ips.len()
			);
			let expiry = Instant::now() + Duration::from_secs(ttl as u64);
			CACHE
				.write()
				.insert(host.to_string(), (ips.clone(), expiry));
			return Some(SocketAddr::new(IpAddr::V4(ips[0]), port));
		}
		debug!(
			"{proto}: no answer for {host} in round {}/{rounds}, retrying",
			round + 1
		);
	}
	debug!(
		"{proto}: resolution failed for {host} after {rounds} rounds ({}ms)",
		start.elapsed().as_millis()
	);
	None
}

/// One DoT round: fire an A query at EVERY resolver concurrently and return the
/// first valid, non-empty answer (with the resolver address that produced it). A
/// resolver that errors or times out is simply outrun.
async fn race_dot(tunnel: &Tunnel, host: &str) -> Option<(SocketAddr, Vec<Ipv4Addr>, u32)> {
	let mut inflight = FuturesUnordered::new();
	for resolver in &DOT_RESOLVERS {
		inflight.push(async move {
			let answer = tokio::time::timeout(DOT_QUERY_TIMEOUT, query_dot(tunnel, host, resolver))
				.await
				.ok()
				.flatten();
			(resolver.addr, answer)
		});
	}
	while let Some((addr, answer)) = inflight.next().await {
		if let Some((ips, ttl)) = answer
			&& !ips.is_empty()
		{
			return Some((addr, ips, ttl));
		}
	}
	None
}

/// One DoT A query/response over the tunnel against `resolver`: TCP connect
/// through the mixnet, TLS (rustls, webpki roots, SNI-validated), then the DNS
/// message framed with its 2-byte big-endian length, and the length-framed
/// response read back.
async fn query_dot(
	tunnel: &Tunnel,
	host: &str,
	resolver: &DotResolver,
) -> Option<(Vec<Ipv4Addr>, u32)> {
	let tcp = tunnel
		.tcp_connect(resolver.addr)
		.await
		.map_err(|e| debug!("dot-dns: connect to {} failed: {e}", resolver.addr))
		.ok()?;
	let server_name = rustls::pki_types::ServerName::try_from(resolver.sni.to_string()).ok()?;
	let mut tls = tokio_rustls::TlsConnector::from(super::tls_config())
		.connect(server_name, tcp)
		.await
		.map_err(|e| debug!("dot-dns: tls handshake with {} failed: {e}", resolver.sni))
		.ok()?;

	let id = rand::random::<u16>();
	let query = encode_query(id, host)?;
	// RFC 7858 / RFC 1035 §4.2.2: 2-byte big-endian length prefix + message.
	let mut framed = Vec::with_capacity(2 + query.len());
	framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
	framed.extend_from_slice(&query);
	tls.write_all(&framed)
		.await
		.map_err(|e| debug!("dot-dns: send to {} failed: {e}", resolver.sni))
		.ok()?;
	tls.flush().await.ok()?;

	let mut len_buf = [0u8; 2];
	tls.read_exact(&mut len_buf)
		.await
		.map_err(|e| debug!("dot-dns: recv len from {} failed: {e}", resolver.sni))
		.ok()?;
	let len = u16::from_be_bytes(len_buf) as usize;
	if len == 0 {
		return None;
	}
	let mut resp = vec![0u8; len];
	tls.read_exact(&mut resp)
		.await
		.map_err(|e| debug!("dot-dns: recv body from {} failed: {e}", resolver.sni))
		.ok()?;
	parse_response(id, &resp)
}

/// One DoH round: race both resolvers and take the first valid, non-empty
/// answer (with the resolver IP that produced it).
async fn race_doh(tunnel: &Tunnel, host: &str) -> Option<(SocketAddr, Vec<Ipv4Addr>, u32)> {
	let mut inflight = FuturesUnordered::new();
	for resolver in &DOH_RESOLVERS {
		inflight.push(async move {
			let answer = tokio::time::timeout(DOH_QUERY_TIMEOUT, query_doh(tunnel, host, resolver))
				.await
				.ok()
				.flatten();
			(resolver.ip, answer)
		});
	}
	while let Some((ip, answer)) = inflight.next().await {
		if let Some((ips, ttl)) = answer
			&& !ips.is_empty()
		{
			return Some((ip, ips, ttl));
		}
	}
	None
}

/// One DoH A query over the tunnel against `resolver` (RFC 8484): TCP connect
/// through the mixnet, TLS (SNI-validated), then an HTTP/1.1 POST to the
/// resolver's /dns-query with the wire-format DNS message as the body and
/// `application/dns-message` content type; the wire-format response body is
/// parsed the same way as DoT/UDP.
async fn query_doh(
	tunnel: &Tunnel,
	host: &str,
	resolver: &DohResolver,
) -> Option<(Vec<Ipv4Addr>, u32)> {
	let id = rand::random::<u16>();
	let query = encode_query(id, host)?;

	let tcp = tunnel
		.tcp_connect(resolver.ip)
		.await
		.map_err(|e| debug!("doh-dns: connect to {} failed: {e}", resolver.ip))
		.ok()?;
	let server_name = rustls::pki_types::ServerName::try_from(resolver.sni.to_string()).ok()?;
	let tls = tokio_rustls::TlsConnector::from(super::tls_config())
		.connect(server_name, tcp)
		.await
		.map_err(|e| debug!("doh-dns: tls handshake with {} failed: {e}", resolver.sni))
		.ok()?;

	let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
		.await
		.map_err(|e| debug!("doh-dns: http handshake with {} failed: {e}", resolver.host))
		.ok()?;
	tokio::spawn(async move {
		let _ = conn.await;
	});

	let req = hyper::Request::builder()
		.method(hyper::Method::POST)
		.uri(resolver.path)
		.header(hyper::header::HOST, resolver.host)
		.header(hyper::header::CONTENT_TYPE, "application/dns-message")
		.header(hyper::header::ACCEPT, "application/dns-message")
		.header(hyper::header::USER_AGENT, "goblin-wallet")
		.body(Full::new(Bytes::from(query)))
		.ok()?;
	let resp = sender
		.send_request(req)
		.await
		.map_err(|e| debug!("doh-dns: request to {} failed: {e}", resolver.host))
		.ok()?;
	if resp.status() != hyper::StatusCode::OK {
		debug!("doh-dns: {} returned {}", resolver.host, resp.status());
		return None;
	}
	let body = resp.into_body().collect().await.ok()?.to_bytes();
	parse_response(id, &body)
}

/// Resolve a batch of hosts concurrently to populate the cache, so the first
/// real use (relay dial, NIP-05 name claim, price fetch) hits a warm entry
/// instead of paying the mixnet DoT round trip inline. Best-effort; the port is
/// irrelevant here (only the host-keyed cache is filled) so a placeholder is used.
pub async fn prewarm(tunnel: &Tunnel, hosts: &[String]) {
	// Mark these as known/stable so they get the long TTL floor and serve-stale.
	{
		let mut known = KNOWN.write();
		for host in hosts {
			known.insert(host.clone());
		}
	}
	let mut inflight = FuturesUnordered::new();
	for host in hosts {
		inflight.push(resolve(tunnel, host, 0));
	}
	while inflight.next().await.is_some() {}
}

/// A cache lookup outcome for `host`: fresh (within TTL) or stale (expired but
/// still remembered, usable via serve-stale for known hosts).
enum CacheHit {
	Fresh(Ipv4Addr),
	Stale(Ipv4Addr),
}

/// Look up `host` in the cache, distinguishing fresh from stale entries. Returns
/// `None` only when the host has never been resolved.
fn cache_hit(host: &str) -> Option<CacheHit> {
	let cache = CACHE.read();
	let (ips, expiry) = cache.get(host)?;
	let ip = ips.first().copied()?;
	Some(if Instant::now() < *expiry {
		CacheHit::Fresh(ip)
	} else {
		CacheHit::Stale(ip)
	})
}

/// Stable public addresses the liveness probe RACES through the tunnel: a tunnel
/// is alive if it can reach ANY of them. Racing (not one fixed target) is why a
/// momentarily slow path to a single resolver no longer false-declares a healthy
/// exit DEAD — the same reason the DoT/DoH resolvers above are raced, not tried in
/// series. Both are anycast resolvers on :443 (never exit-policy-firewalled, since
/// relays + HTTPS already ride it) and effectively always-on.
const PROBE_ADDRS: [SocketAddr; 2] = [
	SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
	SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 443),
];
/// Per-target connect wait; a mixnet TCP handshake is a few seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// Probe rounds before a tunnel is declared dead. A single lost mixnet packet
/// mid-handshake should not condemn a whole tunnel, so an all-miss round is
/// retried once (mirrors the DoT/DoH round loop). Only a tunnel that reaches
/// NEITHER stable target across BOTH rounds is DEAD — this is what stops a
/// healthy-but-unlucky tunnel from being thrown away and reselected forever.
const PROBE_ROUNDS: usize = 2;

/// End-to-end exit-liveness probe: try to open a TCP connection THROUGH the tunnel
/// to any of a few stable public addresses (raced, retried a round) and drop the
/// winner immediately. Because TCP over the mixnet RETRANSMITS, a single lost
/// datagram does not spuriously fail a healthy exit; racing several targets over
/// two rounds additionally absorbs a momentarily slow single path — together they
/// stop the false-DEAD reselect churn the old single-target probe caused. Proves
/// the full path (mixnet → IPR exit → internet) and keeps the gateway/IPR session
/// from idling out. Used by the fresh-tunnel gate and the watchdog keepalive.
pub async fn probe(tunnel: &Tunnel) -> bool {
	for round in 0..PROBE_ROUNDS {
		let mut inflight = FuturesUnordered::new();
		for addr in PROBE_ADDRS {
			inflight.push(async move {
				matches!(
					tokio::time::timeout(PROBE_TIMEOUT, tunnel.tcp_connect(addr)).await,
					Ok(Ok(_))
				)
			});
		}
		while let Some(reached) = inflight.next().await {
			if reached {
				return true;
			}
		}
		debug!(
			"probe: no stable target reachable through tunnel (round {}/{PROBE_ROUNDS})",
			round + 1
		);
	}
	debug!("probe: tunnel failed liveness — reached no stable target in {PROBE_ROUNDS} rounds");
	false
}

/// Encode a recursive A query for `host` with transaction id `id`.
fn encode_query(id: u16, host: &str) -> Option<Vec<u8>> {
	let name = Name::from_ascii(host).ok()?;
	let mut msg = Message::query();
	msg.metadata.id = id;
	msg.metadata.recursion_desired = true;
	msg.add_query(Query::query(name, RecordType::A));
	msg.to_vec().ok()
}

/// Parse a response to transaction `id`: all A records in the answer section
/// plus the smallest TTL among them. `None` on id mismatch, non-response,
/// error rcode or no A records (CNAMEs and other types are skipped).
fn parse_response(id: u16, raw: &[u8]) -> Option<(Vec<Ipv4Addr>, u32)> {
	let msg = Message::from_vec(raw).ok()?;
	if msg.metadata.id != id
		|| msg.metadata.message_type != MessageType::Response
		|| msg.metadata.response_code != ResponseCode::NoError
	{
		return None;
	}
	let mut ips = Vec::new();
	let mut ttl = u32::MAX;
	for record in &msg.answers {
		if let RData::A(a) = record.data {
			ips.push(a.0);
			ttl = ttl.min(record.ttl);
		}
	}
	if ips.is_empty() {
		None
	} else {
		Some((ips, ttl))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Query for `example.com` A/IN, id 0x1234, RD set — the canonical fixture
	/// (same bytes smolmix's own docs use).
	const QUERY_FIXTURE: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
	                               \x07example\x03com\x00\x00\x01\x00\x01";

	/// Response to `QUERY_FIXTURE`: flags 0x8180 (QR, RD, RA, NOERROR), one
	/// question, two answers — a CNAME (ttl 3600, rdata = compression pointer
	/// back to the qname) that must be skipped, then an A record for
	/// 93.184.216.34 with ttl 300.
	const RESPONSE_FIXTURE: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\
	                                  \x07example\x03com\x00\x00\x01\x00\x01\
	                                  \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\x00\x02\xc0\x0c\
	                                  \xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22";

	#[test]
	fn encode_query_matches_fixture() {
		let bytes = encode_query(0x1234, "example.com").unwrap();
		assert_eq!(bytes, QUERY_FIXTURE);
	}

	#[test]
	fn parse_response_extracts_a_records_and_min_ttl() {
		let (ips, ttl) = parse_response(0x1234, RESPONSE_FIXTURE).unwrap();
		assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
		// The CNAME's larger ttl (3600) must not win: only A records count.
		assert_eq!(ttl, 300);
	}

	#[test]
	fn parse_response_rejects_wrong_id() {
		assert!(parse_response(0x5678, RESPONSE_FIXTURE).is_none());
	}

	#[test]
	fn parse_response_rejects_query_and_garbage() {
		// A query (QR=0) is not an answer.
		assert!(parse_response(0x1234, QUERY_FIXTURE).is_none());
		// Truncated/garbage input parses to nothing.
		assert!(parse_response(0x1234, &RESPONSE_FIXTURE[..7]).is_none());
		assert!(parse_response(0x1234, b"\x00").is_none());
	}

	#[test]
	fn parse_response_rejects_error_rcode() {
		// Same fixture with rcode NXDOMAIN (flags 0x8183) and no answers.
		let nx: &[u8] = b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\
		                  \x07example\x03com\x00\x00\x01\x00\x01";
		assert!(parse_response(0x1234, nx).is_none());
	}

	#[test]
	fn ttl_clamp_bounds() {
		assert_eq!(5u32.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS), 60);
		assert_eq!(999_999u32.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS), 3600);
		assert_eq!(300u32.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS), 300);
	}
}
