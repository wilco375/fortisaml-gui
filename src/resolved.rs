//! Full tunnel: send all DNS queries to the VPN link through systemd-resolved's D-Bus API (what
//! `resolvectl domain <if> '~.'` and `resolvectl default-route <if> yes` do). The VPN's DNS servers themselves reach the
//! system through charon's resolve plugin and resolvconf(8); this only adds the routing. resolved accepts these calls
//! from root without asking polkit, so they run before the privilege drop. Without resolved there is nothing to route:
//! resolvconf then makes the VPN servers the system's servers anyway.

#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait Manager {
    fn set_link_domains(&self, ifindex: i32, domains: &[(&str, bool)]) -> zbus::Result<()>;
    fn set_link_default_route(&self, ifindex: i32, enable: bool) -> zbus::Result<()>;
}

/// The routing-only domain "." : every query.
pub const ROUTE_ALL: [(&str, bool); 1] = [(".", true)];

/// Route all DNS queries to interface `ifindex`.
pub fn route_all_queries(ifindex: u32) -> Result<(), String> {
    let conn = zbus::blocking::Connection::system().map_err(|e| format!("system D-Bus: {e}"))?;
    let m = ManagerProxyBlocking::new(&conn).map_err(|e| format!("systemd-resolved: {e}"))?;
    let i = ifindex as i32;
    m.set_link_domains(i, &ROUTE_ALL).map_err(|e| format!("systemd-resolved SetLinkDomains: {e}"))?;
    m.set_link_default_route(i, true).map_err(|e| format!("systemd-resolved SetLinkDefaultRoute: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_queries_route_to_the_vpn() {
        assert_eq!(ROUTE_ALL, [(".", true)]);
    }
}
