//! Kernel network setup over netlink (rtnetlink, smol socket): the xfrm interface, its address, routes and the IPv6
//! block. Every function takes typed values only and runs one blocking request; no commands, no text parsing.

use crate::net::{IfName, Ipv4Net, Mtu};
use futures_util::{
    future::{select, Either},
    pin_mut, TryStreamExt,
};
use netlink_packet_route::link::{InfoData, InfoKind, InfoXfrm, LinkAttribute, LinkInfo, LinkMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use netlink_sys::SmolSocket;
use rtnetlink::{Handle, LinkUnspec, LinkXfrm, RouteMessageBuilder};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

/// Routes we add carry this protocol number, so they can always be found again (also after a crash).
pub const RT_PROTO: u8 = 233;
/// xfrm interface id shared by the interface and charon's SAs/policies.
pub const IF_ID: u32 = 0x5a17;

/// A kernel interface index. Only this module makes one, from a lookup or from a link it just created, so it named a
/// real interface when it was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfIndex(NonZeroU32);

impl IfIndex {
    fn from_kernel(i: u32) -> Result<Self, String> {
        NonZeroU32::new(i).map(Self).ok_or_else(|| "the kernel reported interface index 0".to_string())
    }
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// Run `f` with a fresh netlink handle, driving the connection on this thread until `f` finishes.
fn with_handle<T>(f: impl AsyncFnOnce(Handle) -> Result<T, rtnetlink::Error>) -> Result<T, String> {
    let (conn, handle, _) = rtnetlink::new_connection_with_socket::<SmolSocket>().map_err(|e| format!("netlink: {e}"))?;
    async_io::block_on(async {
        let op = f(handle);
        pin_mut!(conn, op);
        match select(op, conn).await {
            Either::Left((r, _)) => r.map_err(|e| e.to_string()),
            Either::Right(_) => Err("netlink connection closed".into()),
        }
    })
}

fn get_link(name: &IfName) -> Result<Option<LinkMessage>, String> {
    with_handle(async |h| {
        let mut links = h.link().get().match_name(name.to_string()).execute();
        match links.try_next().await {
            Ok(l) => Ok(l),
            // ENODEV: no such interface
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(None),
            Err(e) => Err(e),
        }
    })
}

/// Whether `l` is an xfrm interface bound to our `IF_ID`, i.e. one we created.
fn is_ours(l: &LinkMessage) -> bool {
    l.attributes.iter().any(|a| match a {
        LinkAttribute::LinkInfo(info) => {
            info.contains(&LinkInfo::Kind(InfoKind::Xfrm))
                && info.iter().any(|i| matches!(i, LinkInfo::Data(InfoData::Xfrm(d)) if d.contains(&InfoXfrm::IfId(IF_ID))))
        }
        _ => false,
    })
}

/// Index of the interface `name`, or None if it doesn't exist.
pub fn link_index(name: &IfName) -> Result<Option<IfIndex>, String> {
    get_link(name)?.map(|l| IfIndex::from_kernel(l.header.index)).transpose()
}

/// Create the xfrm interface `name` bound to `IF_ID`; returns its index.
pub fn add_xfrm_link(name: &IfName) -> Result<IfIndex, String> {
    with_handle(async |h| h.link().add(LinkXfrm::new(&name.to_string(), 0, IF_ID).build()).execute().await)?;
    link_index(name)?.ok_or_else(|| format!("interface {name} vanished right after creating it"))
}

/// Set MTU and bring the interface up.
pub fn link_up(index: IfIndex, mtu: Mtu) -> Result<(), String> {
    with_handle(async |h| h.link().set(LinkUnspec::new_with_index(index.get()).mtu(u16::from(mtu).into()).up().build()).execute().await)
}

/// Delete interface `index` (also drops its addresses and routes, and resolved's per-link DNS).
pub fn del_link(index: IfIndex) -> Result<(), String> {
    with_handle(async |h| h.link().del(index.get()).execute().await)
}

/// Add `addr/32` to interface `index`.
pub fn add_addr(index: IfIndex, addr: Ipv4Addr) -> Result<(), String> {
    with_handle(async |h| h.address().add(index.get(), addr.into(), 32).execute().await)
}

fn v4_route(net: Ipv4Net) -> RouteMessageBuilder<Ipv4Addr> {
    RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(net.addr(), net.prefix()).protocol(RouteProtocol::Other(RT_PROTO))
}

/// Route `net` through interface `index`, with `src` as preferred source address.
pub fn add_route(net: Ipv4Net, index: IfIndex, src: Option<Ipv4Addr>) -> Result<(), String> {
    let mut b = v4_route(net).output_interface(index.get()).scope(RouteScope::Link);
    if let Some(s) = src {
        b = b.pref_source(s);
    }
    with_handle(async |h| h.route().add(b.build()).execute().await)
}

/// Route `net` via `gateway` on interface `index` (the host route that keeps the VPN gateway reachable outside the
/// tunnel in full-tunnel mode). An existing route to `net` (e.g. left by another VPN client) is fine: returns false
/// and leaves it alone.
pub fn add_route_via(net: Ipv4Net, gateway: Option<Ipv4Addr>, index: IfIndex) -> Result<bool, String> {
    let mut b = v4_route(net).output_interface(index.get());
    match gateway {
        Some(g) => b = b.gateway(g),
        None => b = b.scope(RouteScope::Link),
    }
    with_handle(async |h| match h.route().add(b.build()).execute().await {
        Ok(()) => Ok(true),
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::EEXIST => Ok(false),
        Err(e) => Err(e),
    })
}

/// Delete our route to `net` (any scope, like `ip route del`).
pub fn del_route(net: Ipv4Net) -> Result<(), String> {
    with_handle(async |h| h.route().del(v4_route(net).scope(RouteScope::NoWhere).build()).execute().await)
}

/// How the kernel currently reaches `dst`: (gateway, interface index). Used before going full tunnel.
pub fn route_to(dst: Ipv4Addr) -> Result<(Option<Ipv4Addr>, IfIndex), String> {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(dst, 32).build();
    let r = with_handle(async |h| h.route().get(msg).execute().try_next().await)?.ok_or_else(|| format!("no route to {dst}"))?;
    let mut gw = None;
    let mut oif = None;
    for a in &r.attributes {
        match a {
            RouteAttribute::Gateway(RouteAddress::Inet(g)) => gw = Some(*g),
            RouteAttribute::Oif(i) => oif = Some(*i),
            _ => {}
        }
    }
    let oif = oif.ok_or_else(|| format!("route to {dst} has no output interface"))?;
    Ok((gw, IfIndex::from_kernel(oif)?))
}

/// The two halves of IPv6 the block makes unreachable: `::/1` and `8000::/1`.
const V6_HALVES: [Ipv6Addr; 2] = [Ipv6Addr::UNSPECIFIED, Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)];

fn v6_unreachable(dst: Ipv6Addr) -> RouteMessage {
    RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(dst, 1)
        .kind(RouteType::Unreachable)
        .priority(1)
        .protocol(RouteProtocol::Other(RT_PROTO))
        .build()
}

/// Block IPv6 while all IPv4 goes through the tunnel: unreachable `::/1` and `8000::/1`, metric 1.
pub fn add_ipv6_block() -> Result<(), String> {
    for dst in V6_HALVES {
        with_handle(async |h| h.route().add(v6_unreachable(dst)).execute().await)?;
    }
    Ok(())
}

pub fn del_ipv6_block() -> Result<(), String> {
    let mut first_err = Ok(());
    for dst in V6_HALVES {
        let r = with_handle(async |h| h.route().del(v6_unreachable(dst)).execute().await);
        if first_err.is_ok() {
            first_err = r;
        }
    }
    first_err
}

/// All routes (IPv4 and IPv6) tagged with `RT_PROTO`.
fn our_routes() -> Result<Vec<RouteMessage>, String> {
    let mut out = Vec::new();
    for v6 in [false, true] {
        let msg = if v6 { RouteMessageBuilder::<Ipv6Addr>::new().build() } else { RouteMessageBuilder::<Ipv4Addr>::new().build() };
        let all: Vec<RouteMessage> = with_handle(async |h| h.route().get(msg).execute().try_collect().await)?;
        out.extend(all.into_iter().filter(|r| r.header.protocol == RouteProtocol::Other(RT_PROTO)));
    }
    Ok(out)
}

/// Remove leftovers of a session that died without cleanup: routes tagged `RT_PROTO` and the interface `name`.
/// Returns the number of items removed.
pub fn purge(name: &IfName) -> Result<usize, String> {
    let mut n = 0;
    for r in our_routes()? {
        // a route can already be gone with its interface; that's fine
        if with_handle(async |h| h.route().del(r).execute().await).is_ok() {
            n += 1;
        }
    }
    if let Some(l) = get_link(name)? {
        // never delete someone else's interface (a profile could name docker0 or wg0)
        if !is_ours(&l) {
            return Err(format!(
                "interface {name} exists and isn't an Archway interface (xfrm, if_id {IF_ID:#x}); choose another interface name"
            ));
        }
        del_link(IfIndex::from_kernel(l.header.index)?)?;
        n += 1;
    }
    Ok(n)
}

/// A route someone else added (no `RT_PROTO` tag), for the kernel tests.
#[cfg(test)]
pub fn add_foreign_route_for_tests(net: Ipv4Net, gateway: Ipv4Addr, index: IfIndex) -> Result<(), String> {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(net.addr(), net.prefix()).gateway(gateway).output_interface(index.get()).build();
    with_handle(async |h| h.route().add(msg).execute().await)
}

/// A dummy "uplink" with an address, for the kernel tests.
#[cfg(test)]
pub fn add_dummy_for_tests(name: &IfName, addr: Ipv4Addr, prefix: u8) -> Result<(), String> {
    with_handle(async |h| h.link().add(rtnetlink::LinkDummy::new(&name.to_string()).build()).execute().await)?;
    let i = link_index(name)?.ok_or("dummy interface missing")?;
    link_up(i, Mtu::try_from(1500).expect("in range"))?;
    // the kernel adds its own link route for the prefix
    with_handle(async |h| h.address().add(i.get(), addr.into(), prefix).execute().await)
}

#[cfg(test)]
mod tests {
    //! Real kernel tests. They need CAP_NET_ADMIN in a throwaway network namespace, so they're ignored by default;
    //! run them with `scripts/netns-test.sh`.
    use super::*;

    fn ifn() -> IfName {
        "archwaytest0".parse().unwrap()
    }

    #[test]
    #[ignore]
    fn xfrm_link_address_routes_and_purge() {
        let i = add_xfrm_link(&ifn()).unwrap();
        assert_eq!(link_index(&ifn()).unwrap(), Some(i));
        link_up(i, Mtu::try_from(1400).unwrap()).unwrap();
        add_addr(i, Ipv4Addr::new(10, 98, 0, 2)).unwrap();
        add_route("10.10.0.0/16".parse().unwrap(), i, Some(Ipv4Addr::new(10, 98, 0, 2))).unwrap();
        add_ipv6_block().unwrap();
        assert_eq!(our_routes().unwrap().len(), 3);
        del_route("10.10.0.0/16".parse().unwrap()).unwrap();
        assert_eq!(our_routes().unwrap().len(), 2);
        assert_eq!(purge(&ifn()).unwrap(), 3, "two IPv6 routes + the interface");
        assert_eq!(link_index(&ifn()).unwrap(), None);
        assert!(our_routes().unwrap().is_empty());
        assert_eq!(purge(&ifn()).unwrap(), 0, "purge is idempotent");
    }

    #[test]
    #[ignore]
    fn purge_refuses_a_foreign_interface_with_our_name() {
        // e.g. a shared profile with ifname = "docker0": must not delete someone else's interface as root
        let n = ifn();
        add_dummy_for_tests(&n, Ipv4Addr::new(192, 0, 2, 10), 24).unwrap();
        let e = purge(&n).unwrap_err();
        assert!(e.contains("isn't an Archway interface"), "{e}");
        assert!(link_index(&n).unwrap().is_some(), "left alone");
        assert!(add_xfrm_link(&n).is_err(), "and not taken over either");
    }

    #[test]
    #[ignore]
    fn route_to_finds_the_path_and_host_route_goes_via_it() {
        // a dummy uplink with a default route, like a real machine
        let up: IfName = "archwayup0".parse().unwrap();
        add_dummy_for_tests(&up, Ipv4Addr::new(192, 0, 2, 10), 24).unwrap();
        let ui = link_index(&up).unwrap().unwrap();
        add_route_via("0.0.0.0/0".parse().unwrap(), Some(Ipv4Addr::new(192, 0, 2, 1)), ui).unwrap();
        let (gw, oif) = route_to(Ipv4Addr::new(198, 51, 100, 7)).unwrap();
        assert_eq!((gw, oif), (Some(Ipv4Addr::new(192, 0, 2, 1)), ui));
        add_route_via("198.51.100.7/32".parse().unwrap(), gw, oif).unwrap();
        assert_eq!(purge(&"archwaynone0".parse().unwrap()).unwrap(), 2, "our default + host route");
        del_link(ui).unwrap();
    }
}
