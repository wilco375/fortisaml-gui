//! Tunnel plumbing: our xfrm interface (bound to charon's SAs by `IF_ID`), and once charon has the SA up the virtual
//! IP, routes, the IPv6 block and, in full tunnel, DNS routing. Every step records how to undo it.

use crate::charon::Established;
use crate::net::{IfName, Ipv4Net, Mtu};
use crate::netlink::{self, IfIndex};
use crate::resolved;

pub struct TunnelOpts {
    pub ifname: IfName,
    pub mtu: Mtu,
    /// None = use the gateway's traffic selectors; Some = override (0.0.0.0/0 = full tunnel)
    pub routes: Option<Vec<Ipv4Net>>,
    pub block_ipv6: bool,
    pub set_dns: bool,
}

#[derive(Debug, PartialEq)]
enum Undo {
    Link(IfIndex),
    Route(Ipv4Net),
    Ipv6Block,
}

pub struct Tunnel {
    undo: Vec<Undo>,
    pub index: IfIndex,
    pub routes: Vec<Ipv4Net>,
    pub full: bool,
}

impl Tunnel {
    /// Create the xfrm interface. Done before the IKE negotiation, so charon can hand the VPN's DNS servers to
    /// resolvconf for this interface as soon as it gets them.
    pub fn create(o: &TunnelOpts, log: &dyn Fn(String)) -> Result<Tunnel, String> {
        log(format!("creating xfrm interface {} (if_id {:#x})", o.ifname, netlink::IF_ID));
        let index = netlink::add_xfrm_link(&o.ifname)?;
        Ok(Tunnel { undo: vec![Undo::Link(index)], index, routes: vec![], full: false })
    }

    /// Bring the interface up with what the gateway assigned. On error the caller runs `down`.
    pub fn configure(&mut self, est: &Established, o: &TunnelOpts, log: &dyn Fn(String)) -> Result<(), String> {
        netlink::link_up(self.index, o.mtu)?;
        netlink::add_addr(self.index, est.vip)?;
        let mut routes = o.routes.clone().unwrap_or_else(|| est.remote_ts.clone());
        self.full = routes.iter().any(|r| r.prefix() == 0);
        if self.full {
            // keep the gateway reachable outside the tunnel, then cover 0/0 with two /1 routes
            let (via, oif) = netlink::route_to(est.gateway)?;
            let host = Ipv4Net::new(est.gateway, 32)?;
            if netlink::add_route_via(host, via, oif)? {
                self.undo.push(Undo::Route(host));
            } else {
                log(format!("using the existing route to the gateway {}", est.gateway));
            }
            routes = Ipv4Net::HALVES.to_vec();
            if o.block_ipv6 {
                netlink::add_ipv6_block()?;
                self.undo.push(Undo::Ipv6Block);
            }
        }
        for r in &routes {
            log(format!("route {r} via {}", o.ifname));
            match netlink::add_route(*r, self.index, Some(est.vip)) {
                Ok(()) => self.undo.push(Undo::Route(*r)),
                Err(e) => log(format!("WARNING: route {r}: {e}")),
            }
        }
        self.routes = routes;
        if o.set_dns && self.full {
            // a DNS failure leaves a working tunnel: warn, don't fail
            if let Err(e) = resolved::route_all_queries(self.index.get()) {
                log(format!("WARNING: DNS queries not routed through the VPN: {e}"));
            }
        }
        Ok(())
    }

    /// Undo everything, newest first; each step independent.
    pub fn down(&mut self, log: &dyn Fn(String)) {
        while let Some(u) = self.undo.pop() {
            let r = match &u {
                Undo::Link(i) => netlink::del_link(*i),
                Undo::Route(n) => netlink::del_route(*n),
                Undo::Ipv6Block => netlink::del_ipv6_block(),
            };
            if let Err(e) = r {
                log(format!("cleanup {u:?}: {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Real kernel tests in a throwaway network namespace: run with `scripts/netns-test.sh`.
    use super::*;
    use std::net::Ipv4Addr;

    fn est(remote_ts: &[&str]) -> Established {
        Established {
            gateway: Ipv4Addr::new(198, 51, 100, 7),
            vip: Ipv4Addr::new(10, 98, 0, 2),
            remote_ts: remote_ts.iter().map(|t| t.parse().unwrap()).collect(),
        }
    }

    fn opts(routes: Option<Vec<Ipv4Net>>) -> TunnelOpts {
        TunnelOpts { ifname: "fsamltest0".parse().unwrap(), mtu: Mtu::try_from(1400).unwrap(), routes, block_ipv6: true, set_dns: false }
    }

    fn quiet(_: String) {}

    #[test]
    #[ignore]
    fn split_tunnel_up_and_down() {
        let mut t = Tunnel::create(&opts(None), &quiet).unwrap();
        t.configure(&est(&["10.10.0.0/16", "10.20.0.0/16"]), &opts(None), &quiet).unwrap();
        assert!(!t.full);
        assert_eq!(t.routes.len(), 2);
        assert!(netlink::link_index(&"fsamltest0".parse().unwrap()).unwrap().is_some());
        t.down(&quiet);
        assert!(netlink::link_index(&"fsamltest0".parse().unwrap()).unwrap().is_none());
        assert_eq!(netlink::purge(&"fsamltest0".parse().unwrap()).unwrap(), 0, "nothing left behind");
    }

    #[test]
    #[ignore]
    fn full_tunnel_keeps_gateway_route_and_blocks_ipv6() {
        // uplink with a default route, as on a real machine
        let up: IfName = "fsamlup0".parse().unwrap();
        netlink::add_dummy_for_tests(&up, Ipv4Addr::new(192, 0, 2, 10), 24).unwrap();
        let ui = netlink::link_index(&up).unwrap().unwrap();
        netlink::add_route_via("0.0.0.0/0".parse().unwrap(), Some(Ipv4Addr::new(192, 0, 2, 1)), ui).unwrap();

        let mut t = Tunnel::create(&opts(None), &quiet).unwrap();
        t.configure(&est(&["0.0.0.0/0"]), &opts(None), &quiet).unwrap();
        assert!(t.full);
        assert_eq!(t.routes, Ipv4Net::HALVES);
        assert_eq!(netlink::route_to(Ipv4Addr::new(198, 51, 100, 7)).unwrap(), (Some(Ipv4Addr::new(192, 0, 2, 1)), ui), "gateway stays outside");
        assert_eq!(netlink::route_to(Ipv4Addr::new(203, 0, 113, 9)).unwrap().1, t.index, "everything else goes in");
        t.down(&quiet);
        assert_eq!(netlink::route_to(Ipv4Addr::new(203, 0, 113, 9)).unwrap().1, ui, "back to normal");
    }

    #[test]
    #[ignore]
    fn existing_route_to_the_gateway_is_used_and_left_alone() {
        // e.g. left behind by another VPN client: full tunnel must still work, and not delete it afterwards
        let up: IfName = "fsamlup0".parse().unwrap();
        netlink::add_dummy_for_tests(&up, Ipv4Addr::new(192, 0, 2, 10), 24).unwrap();
        let ui = netlink::link_index(&up).unwrap().unwrap();
        netlink::add_route_via("0.0.0.0/0".parse().unwrap(), Some(Ipv4Addr::new(192, 0, 2, 1)), ui).unwrap();
        netlink::add_foreign_route_for_tests("198.51.100.7/32".parse().unwrap(), Ipv4Addr::new(192, 0, 2, 1), ui).unwrap();

        let mut t = Tunnel::create(&opts(None), &quiet).unwrap();
        t.configure(&est(&["0.0.0.0/0"]), &opts(None), &quiet).unwrap();
        t.down(&quiet);
        assert_eq!(netlink::route_to(Ipv4Addr::new(198, 51, 100, 7)).unwrap(), (Some(Ipv4Addr::new(192, 0, 2, 1)), ui), "still there");
    }

    #[test]
    #[ignore]
    fn failure_midway_undoes_earlier_steps() {
        // full tunnel without any route to the gateway: route_to fails after the interface exists
        let mut t = Tunnel::create(&opts(None), &quiet).unwrap();
        let e = t.configure(&est(&["0.0.0.0/0"]), &opts(None), &quiet).unwrap_err();
        assert!(e.contains("198.51.100.7") || e.contains("unreachable"), "{e}");
        t.down(&quiet);
        assert!(netlink::link_index(&"fsamltest0".parse().unwrap()).unwrap().is_none(), "interface removed again");
    }
}
