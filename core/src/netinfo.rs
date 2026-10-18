//! Socket setup and candidate gathering: every address at which the peer might reach us.

use crate::stun;
use crate::TUN_NET_PREFIX;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::channel;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct GatherOpts {
    pub stun_servers: Vec<String>,
    pub upnp: bool,
    /// Try to bind this UDP port first (stable port = friendlier to NATs and UPnP); 0 = any.
    pub preferred_port: u16,
    /// Also offer 127.0.0.1 (tests / two instances on one machine).
    pub loopback: bool,
}

impl Default for GatherOpts {
    fn default() -> Self {
        Self {
            stun_servers: stun::DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect(),
            upnp: true,
            preferred_port: 0,
            loopback: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Gathered {
    pub cands: Vec<SocketAddr>,
    /// Public address as seen by STUN.
    pub public: Option<SocketAddr>,
    /// Different STUN servers saw different ports: "hard" NAT, punching likely fails.
    pub symmetric: bool,
    pub upnp: Option<SocketAddr>,
}

impl Gathered {
    pub fn describe(&self) -> String {
        format!(
            "public={} upnp={} symmetric_nat={} cands={}",
            self.public.map(|a| a.to_string()).unwrap_or("-".into()),
            self.upnp.map(|a| a.to_string()).unwrap_or("-".into()),
            self.symmetric,
            self.cands.len()
        )
    }
}

/// UDP socket with large buffers (video frames arrive in bursts of hundreds of packets).
pub fn bind_socket(preferred_port: u16) -> std::io::Result<UdpSocket> {
    let make = |port: u16| -> std::io::Result<UdpSocket> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = s.set_recv_buffer_size(4 << 20);
        let _ = s.set_send_buffer_size(4 << 20);
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
        Ok(s.into())
    };
    if preferred_port != 0 {
        if let Ok(s) = make(preferred_port) {
            return Ok(s);
        }
    }
    make(0)
}

fn is_tunnel_ip(ip: &Ipv4Addr) -> bool {
    ip.octets()[..2] == TUN_NET_PREFIX
}

/// LAN IPv4 addresses of this machine (no loopback / link-local / our own tunnel).
pub fn local_ipv4s() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        for i in ifs {
            if let IpAddr::V4(ip) = i.ip() {
                if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !is_tunnel_ip(&ip) {
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out
}

/// The local address used for the default route (no packets are sent).
pub fn default_route_ip() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:80").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

fn try_upnp(local_port: u16) -> Option<SocketAddr> {
    let local_ip = default_route_ip()?;
    let gw = igd_next::search_gateway(igd_next::SearchOptions {
        timeout: Some(Duration::from_millis(2000)),
        ..Default::default()
    })
    .ok()?;
    let ext_ip = gw.get_external_ip().ok()?;
    let local = SocketAddr::V4(SocketAddrV4::new(local_ip, local_port));
    let proto = igd_next::PortMappingProtocol::UDP;
    let ext_port = match gw.add_port(proto, local_port, local, 7200, "LowLag") {
        Ok(()) => local_port,
        Err(_) => gw.add_any_port(proto, local, 7200, "LowLag").ok()?,
    };
    Some(SocketAddr::new(ext_ip, ext_port))
}

/// Is there a UPnP-capable router? Returns a description, without creating any mapping.
pub fn upnp_probe() -> Option<String> {
    let gw = igd_next::search_gateway(igd_next::SearchOptions {
        timeout: Some(Duration::from_millis(2000)),
        ..Default::default()
    })
    .ok()?;
    let ext = gw.get_external_ip().map(|i| i.to_string()).unwrap_or_else(|_| "?".into());
    Some(format!("router {} external {}", gw.addr.ip(), ext))
}

/// Gather candidates for `sock`. Takes up to ~2.5 s (STUN and UPnP run in parallel).
pub fn gather(sock: &UdpSocket, opts: &GatherOpts) -> Gathered {
    let port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
    let (utx, urx) = channel();
    if opts.upnp {
        std::thread::spawn(move || {
            let _ = utx.send(try_upnp(port));
        });
    } else {
        drop(utx);
    }

    let servers = stun::resolve(&opts.stun_servers);
    let answers = stun::query(sock, &servers, Duration::from_millis(1800));
    let mut g = Gathered::default();
    for (_, mapped) in &answers {
        match g.public {
            None => g.public = Some(*mapped),
            Some(p) if p != *mapped => g.symmetric = true,
            _ => {}
        }
    }
    g.upnp = urx.recv_timeout(Duration::from_millis(2500)).ok().flatten();

    let push = |a: SocketAddr, list: &mut Vec<SocketAddr>| {
        if !list.contains(&a) {
            list.push(a);
        }
    };
    let mut cands = Vec::new();
    if let Some(p) = g.public {
        push(p, &mut cands);
    }
    // With a symmetric NAT the port changes per destination; every observed mapping is a guess.
    if g.symmetric {
        for (_, mapped) in &answers {
            push(*mapped, &mut cands);
        }
    }
    if let Some(u) = g.upnp {
        push(u, &mut cands);
    }
    for ip in local_ipv4s() {
        push(SocketAddr::new(IpAddr::V4(ip), port), &mut cands);
    }
    if opts.loopback {
        push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port), &mut cands);
    }
    g.cands = cands;
    g
}

pub fn parse_cands(list: &[String]) -> Vec<SocketAddr> {
    list.iter().filter_map(|s| s.parse().ok()).take(16).collect()
}
