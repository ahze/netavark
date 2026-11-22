//! pf firewall driver for FreeBSD.
//!
//! Rules live in anchors under `netavark/`, loaded with `pfctl -a <anchor>
//! -f -` and flushed with `pfctl -a <anchor> -F rules` and `-F nat`. The host's pf.conf
//! has to include them:
//!
//! ```text
//! table <netavark-subnets> persist
//! table <netavark-isolated> persist
//! nat-anchor "netavark/*"
//! rdr-anchor "netavark/*"
//! anchor "netavark/*"
//! ```
//!
//! One anchor per network holds its NAT and its isolation rules; one per
//! network and container holds that container's port redirects and the
//! loopback hairpin for them. The two tables list every netavark subnet
//! and the subnets of isolated networks; a rule in an anchor that names a
//! table falls back to the main ruleset's table of that name, which is
//! why they are declared there.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use ipnet::IpNet;
use log::{debug, warn};

use crate::error::{ErrorWrap, NetavarkError, NetavarkResult};
use crate::firewall;
use crate::network::core_utils::get_default_route_interface;
use crate::network::internal_types::{
    IsolateOption, PortForwardConfig, SetupNetwork, TearDownNetwork, TeardownPortForward,
};
use crate::network::netlink::Socket;
use crate::network::netlink_route::NetlinkRoute;
use crate::network::types::PortMapping;
use crate::wrap;

const ANCHOR_PREFIX: &str = "netavark/";
/// Every netavark subnet, for strict isolation.
const SUBNETS_TABLE: &str = "netavark-subnets";
/// The subnets of networks with isolate set, for normal isolation.
const ISOLATED_TABLE: &str = "netavark-isolated";

pub struct Pf {}

pub fn new() -> NetavarkResult<Box<dyn firewall::FirewallDriver>> {
    Ok(Box::new(Pf {}))
}

impl firewall::FirewallDriver for Pf {
    fn driver_name(&self) -> &str {
        firewall::PF
    }

    fn setup_network(
        &self,
        network_setup: SetupNetwork,
        _dbus_conn: &Option<zbus::blocking::Connection>,
    ) -> NetavarkResult<()> {
        for subnet in network_setup.subnets.iter().flatten() {
            table_change(SUBNETS_TABLE, "add", subnet)?;
            if isolated(&network_setup) {
                table_change(ISOLATED_TABLE, "add", subnet)?;
            }
        }
        let rules = if network_setup.subnets.is_some() {
            network_rules(&network_setup, &egress_interface()?)
        } else {
            String::new()
        };
        load_anchor(&network_anchor(&network_setup.network_hash_name), &rules)
    }

    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()> {
        if tear.complete_teardown {
            flush_anchor(&network_anchor(&tear.config.network_hash_name))?;
            for subnet in tear.config.subnets.iter().flatten() {
                table_change(SUBNETS_TABLE, "delete", subnet)?;
                if isolated(&tear.config) {
                    table_change(ISOLATED_TABLE, "delete", subnet)?;
                }
            }
        }
        Ok(())
    }

    fn setup_port_forward(
        &self,
        setup_portfw: PortForwardConfig,
        _dbus_conn: &Option<zbus::blocking::Connection>,
    ) -> NetavarkResult<()> {
        let rules = container_rules(&setup_portfw, &interface_for_subnet)?;
        load_anchor(
            &container_anchor(&setup_portfw.network_hash_name, &setup_portfw.container_id),
            &rules,
        )
    }

    fn teardown_port_forward(&self, tear: TeardownPortForward) -> NetavarkResult<()> {
        flush_anchor(&container_anchor(
            &tear.config.network_hash_name,
            &tear.config.container_id,
        ))
    }
}

fn isolated(network_setup: &SetupNetwork) -> bool {
    matches!(
        network_setup.isolation,
        IsolateOption::Normal | IsolateOption::Strict
    )
}

/// The rules of a network. NAT hides each subnet behind `egress` unless
/// the network is internal, which instead may only reach its own bridge
/// (that is where aardvark-dns answers). Isolation keeps the subnet and
/// the other netavark subnets apart, all of them for strict and the
/// isolated ones for normal; the bridge's own subnet is always allowed
/// because that is how containers reach the gateway.
fn network_rules(network_setup: &SetupNetwork, egress: &str) -> String {
    let mut rules = String::new();
    let bridge = &network_setup.bridge_name;
    for subnet in network_setup.subnets.iter().flatten() {
        if network_setup.internal {
            continue;
        }
        match subnet {
            IpNet::V4(_) => {
                let target = match network_setup.outbound_addr4 {
                    Some(addr) => addr.to_string(),
                    None => format!("({egress})"),
                };
                rules.push_str(&format!(
                    "nat on {egress} inet from {subnet} to any -> {target}\n"
                ));
            }
            IpNet::V6(_) => {
                let target = match network_setup.outbound_addr6 {
                    Some(addr) => addr.to_string(),
                    None => format!("({egress})"),
                };
                rules.push_str(&format!(
                    "nat on {egress} inet6 from {subnet} to !ff00::/8 -> {target}\n"
                ));
            }
        }
    }
    for subnet in network_setup.subnets.iter().flatten() {
        let family = if subnet.addr().is_ipv4() {
            "inet"
        } else {
            "inet6"
        };
        if network_setup.internal {
            rules.push_str(&format!(
                "pass in quick on {bridge} {family} from {subnet} to ({bridge})\n\
                 block in quick on {bridge} {family} from {subnet} to any\n"
            ));
            continue;
        }
        let table = match network_setup.isolation {
            IsolateOption::Strict => SUBNETS_TABLE,
            IsolateOption::Normal => ISOLATED_TABLE,
            IsolateOption::Never => continue,
        };
        rules.push_str(&format!(
            "pass in quick on {bridge} {family} from {subnet} to {subnet}\n\
             pass in quick on {bridge} {family} from {subnet} to (self)\n\
             block in quick on {bridge} {family} from {subnet} to <{table}>\n"
        ));
    }
    rules
}

fn table_change(table: &str, op: &str, subnet: &IpNet) -> NetavarkResult<()> {
    debug!("pf table {table}: {op} {subnet}");
    let out = wrap!(
        Command::new("pfctl")
            .args(["-q", "-t", table, "-T", op, &subnet.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output(),
        "run pfctl"
    )?;
    if !out.status.success() {
        return Err(NetavarkError::msg(format!(
            "pfctl -t {table} -T {op} {subnet}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The rules of one container on one network: the DNS redirect when
/// aardvark-dns is not on port 53, and the port mappings. `bridge` names
/// the host interface of a subnet.
fn container_rules(
    setup_portfw: &PortForwardConfig,
    bridge: &dyn Fn(&IpNet) -> Option<String>,
) -> NetavarkResult<String> {
    let mut rules = String::new();

    if setup_portfw.dns_port != 53 {
        for ip in setup_portfw.dns_server_ips {
            let family = if ip.is_ipv4() { "inet" } else { "inet6" };
            rules.push_str(&format!(
                "rdr pass {family} proto {{ tcp, udp }} from any to {ip} port 53 -> {ip} port {}\n",
                setup_portfw.dns_port
            ));
        }
    }

    if !setup_portfw.internal {
        if let (Some(ip), Some(subnet)) = (setup_portfw.container_ip_v4, setup_portfw.subnet_v4) {
            port_rules(&mut rules, ip, subnet, setup_portfw, bridge)?;
        }
        if let (Some(ip), Some(subnet)) = (setup_portfw.container_ip_v6, setup_portfw.subnet_v6) {
            port_rules(&mut rules, ip, subnet, setup_portfw, bridge)?;
        }
    }
    Ok(rules)
}

/// Redirects for one address family of a container, plus the NAT rule on
/// the bridge so replies return through it: limited to loopback and the
/// bridge's own subnet when this is the sole default route, or all
/// sources when another network or `no_default_route` would send replies
/// elsewhere.
fn port_rules(
    rules: &mut String,
    ip: IpAddr,
    subnet: IpNet,
    setup_portfw: &PortForwardConfig,
    bridge: &dyn Fn(&IpNet) -> Option<String>,
) -> NetavarkResult<()> {
    let family = if ip.is_ipv4() { "inet" } else { "inet6" };
    let bridge = bridge(&subnet).ok_or_else(|| {
        NetavarkError::msg(format!("no host interface has an address in {subnet}"))
    })?;
    let nat_src = if setup_portfw.snat_all {
        "any".to_string()
    } else {
        format!("{{ (lo0), {subnet} }}")
    };

    for port in setup_portfw.port_mappings.iter().flatten() {
        let Some(host) = host_address(port, ip.is_ipv4())? else {
            continue;
        };
        let host_ports = port_range(port.host_port, port.range);
        let container_ports = if port.range > 1 {
            format!("{}:*", port.container_port)
        } else {
            port.container_port.to_string()
        };
        for proto in port.protocol.split(',') {
            let proto = proto.trim();
            if proto.is_empty() {
                continue;
            }
            rules.push_str(&format!(
                "rdr pass {family} proto {proto} from any to {host} port {host_ports} -> {ip} port {container_ports}\n"
            ));
            rules.push_str(&format!(
                "nat on {bridge} {family} proto {proto} from {nat_src} to {ip} port {} -> ({bridge})\n",
                port_range(port.container_port, port.range)
            ));
        }
    }
    Ok(())
}

/// The destination the redirect matches: the host IP of the mapping, or
/// every host address. None when the mapping's host IP is for the other
/// address family.
fn host_address(port: &PortMapping, v4: bool) -> NetavarkResult<Option<String>> {
    if port.host_ip.is_empty() || port.host_ip == "0.0.0.0" || port.host_ip == "::" {
        return Ok(Some("(self)".to_string()));
    }
    let host_ip: IpAddr = port.host_ip.parse().map_err(|_| {
        NetavarkError::msg(format!(
            "invalid host ip {} for port {}",
            port.host_ip, port.host_port
        ))
    })?;
    if host_ip.is_ipv4() != v4 {
        return Ok(None);
    }
    Ok(Some(host_ip.to_string()))
}

fn port_range(start: u16, range: u16) -> String {
    if range > 1 {
        format!("{start}:{}", start + range - 1)
    } else {
        start.to_string()
    }
}

fn network_anchor(network_hash_name: &str) -> String {
    format!("{ANCHOR_PREFIX}{network_hash_name}")
}

fn container_anchor(network_hash_name: &str, container_id: &str) -> String {
    let id = container_id.get(..12).unwrap_or(container_id);
    format!("{ANCHOR_PREFIX}{network_hash_name}-{id}")
}

/// The interface the default route leaves through; what the NAT hides
/// the containers behind.
fn egress_interface() -> NetavarkResult<String> {
    let mut host = Socket::<NetlinkRoute>::new().wrap("host netlink socket")?;
    let link = get_default_route_interface(&mut host, None).wrap("find the egress interface")?;
    for nla in link.attributes {
        if let netlink_packet_route::link::LinkAttribute::IfName(name) = nla {
            return Ok(name);
        }
    }
    Err(NetavarkError::msg(
        "the default route interface has no name",
    ))
}

/// The host interface with an address inside `subnet`: the bridge.
fn interface_for_subnet(subnet: &IpNet) -> Option<String> {
    let addrs = match nix::ifaddrs::getifaddrs() {
        Ok(addrs) => addrs,
        Err(e) => {
            warn!("getifaddrs: {e}");
            return None;
        }
    };
    for ifa in addrs {
        let Some(addr) = ifa.address else { continue };
        let ip = if let Some(v4) = addr.as_sockaddr_in() {
            IpAddr::V4(v4.ip())
        } else if let Some(v6) = addr.as_sockaddr_in6() {
            IpAddr::V6(v6.ip())
        } else {
            continue;
        };
        if subnet.contains(&ip) {
            return Some(ifa.interface_name);
        }
    }
    None
}

fn load_anchor(anchor: &str, rules: &str) -> NetavarkResult<()> {
    debug!("loading pf anchor {anchor}:\n{rules}");
    let mut child = wrap!(
        Command::new("pfctl")
            .args(["-q", "-a", anchor, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn(),
        "run pfctl"
    )?;
    wrap!(
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(rules.as_bytes()),
        "write pf rules"
    )?;
    let out = wrap!(child.wait_with_output(), "wait for pfctl")?;
    if !out.status.success() {
        return Err(NetavarkError::msg(format!(
            "pfctl -a {anchor} -f: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Whether `anchor` exists under the netavark anchor. pfctl cannot flush
/// an anchor that was never loaded, and a failed setup may never have
/// loaded one.
fn anchor_exists(anchor: &str) -> bool {
    let parent = ANCHOR_PREFIX.trim_end_matches('/');
    let out = Command::new("pfctl")
        .args(["-q", "-s", "Anchors", "-a", parent])
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|line| line.trim() == anchor),
        _ => false,
    }
}

fn flush_anchor(anchor: &str) -> NetavarkResult<()> {
    if !anchor_exists(anchor) {
        debug!("pf anchor {anchor} does not exist, nothing to flush");
        return Ok(());
    }
    debug!("flushing pf anchor {anchor}");
    // Only the anchor's own rule sets. `-F all` would also flush the
    // global state table and fail on the parts an anchor does not have.
    // An anchor whose rules named a host table stays listed, empty,
    // after this; pf keeps the table reference and nothing clears it.
    for what in ["rules", "nat"] {
        let out = wrap!(
            Command::new("pfctl")
                .args(["-q", "-a", anchor, "-F", what])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output(),
            "run pfctl"
        )?;
        if !out.status.success() {
            return Err(NetavarkError::msg(format!(
                "pfctl -a {anchor} -F {what}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn mapping(
        host_ip: &str,
        host_port: u16,
        container_port: u16,
        proto: &str,
        range: u16,
    ) -> PortMapping {
        PortMapping {
            container_port,
            host_ip: host_ip.to_string(),
            host_port,
            protocol: proto.to_string(),
            range,
        }
    }

    #[test]
    fn network_nat_rules() {
        let setup = SetupNetwork {
            subnets: Some(vec![
                "10.89.0.0/24".parse().unwrap(),
                "fd00:89::/64".parse().unwrap(),
            ]),
            bridge_name: "nvtest0".into(),
            network_id: "id".into(),
            network_hash_name: "hash".into(),
            isolation: IsolateOption::Never,
            dns_port: 53,
            internal: false,
            dns_enabled: true,
            outbound_addr4: None,
            outbound_addr6: None,
        };
        assert_eq!(
            network_rules(&setup, "re0"),
            "nat on re0 inet from 10.89.0.0/24 to any -> (re0)\n\
             nat on re0 inet6 from fd00:89::/64 to !ff00::/8 -> (re0)\n"
        );
        let setup = SetupNetwork {
            outbound_addr4: Some(Ipv4Addr::new(192, 168, 86, 5)),
            subnets: Some(vec!["10.89.0.0/24".parse().unwrap()]),
            ..setup
        };
        assert_eq!(
            network_rules(&setup, "re0"),
            "nat on re0 inet from 10.89.0.0/24 to any -> 192.168.86.5\n"
        );
    }

    #[test]
    fn isolation_and_internal_rules() {
        let setup = SetupNetwork {
            subnets: Some(vec!["10.89.0.0/24".parse().unwrap()]),
            bridge_name: "nvtest0".into(),
            network_id: "id".into(),
            network_hash_name: "hash".into(),
            isolation: IsolateOption::Strict,
            dns_port: 53,
            internal: false,
            dns_enabled: true,
            outbound_addr4: None,
            outbound_addr6: None,
        };
        assert_eq!(
            network_rules(&setup, "re0"),
            "nat on re0 inet from 10.89.0.0/24 to any -> (re0)\n\
             pass in quick on nvtest0 inet from 10.89.0.0/24 to 10.89.0.0/24\n\
             pass in quick on nvtest0 inet from 10.89.0.0/24 to (self)\n\
             block in quick on nvtest0 inet from 10.89.0.0/24 to <netavark-subnets>\n"
        );
        let setup = SetupNetwork {
            isolation: IsolateOption::Normal,
            ..setup
        };
        assert!(network_rules(&setup, "re0").contains("to <netavark-isolated>\n"));
        let setup = SetupNetwork {
            internal: true,
            ..setup
        };
        assert_eq!(
            network_rules(&setup, "re0"),
            "pass in quick on nvtest0 inet from 10.89.0.0/24 to (nvtest0)\n\
             block in quick on nvtest0 inet from 10.89.0.0/24 to any\n"
        );
    }

    #[test]
    fn container_port_rules() {
        let mappings = Some(vec![
            mapping("", 18080, 8000, "tcp", 1),
            mapping("192.168.86.5", 2000, 3000, "udp,tcp", 11),
            mapping("::1", 7, 7, "tcp", 1),
        ]);
        let dns = vec![IpAddr::V4(Ipv4Addr::new(10, 89, 0, 1))];
        let setup = PortForwardConfig {
            container_id: "0123456789abcdef".into(),
            network_id: "id".into(),
            port_mappings: &mappings,
            network_name: "nvtest".into(),
            network_hash_name: "hash".into(),
            container_ip_v4: Some("10.89.0.2".parse().unwrap()),
            subnet_v4: Some("10.89.0.0/24".parse().unwrap()),
            container_ip_v6: None,
            subnet_v6: None,
            dns_port: 5353,
            dns_server_ips: &dns,
            internal: false,
            snat_all: false,
        };
        let bridge = |_: &IpNet| Some("nvtest0".to_string());
        let rules = container_rules(&setup, &bridge).unwrap();
        assert_eq!(
            rules,
            "rdr pass inet proto { tcp, udp } from any to 10.89.0.1 port 53 -> 10.89.0.1 port 5353\n\
             rdr pass inet proto tcp from any to (self) port 18080 -> 10.89.0.2 port 8000\n\
             nat on nvtest0 inet proto tcp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 8000 -> (nvtest0)\n\
             rdr pass inet proto udp from any to 192.168.86.5 port 2000:2010 -> 10.89.0.2 port 3000:*\n\
             nat on nvtest0 inet proto udp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 3000:3010 -> (nvtest0)\n\
             rdr pass inet proto tcp from any to 192.168.86.5 port 2000:2010 -> 10.89.0.2 port 3000:*\n\
             nat on nvtest0 inet proto tcp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 3000:3010 -> (nvtest0)\n"
        );
        assert_eq!(
            container_anchor("hash", "0123456789abcdef"),
            "netavark/hash-0123456789ab"
        );
    }

    #[test]
    fn container_port_rules_snat_all() {
        let mappings = Some(vec![
            mapping("", 18080, 8000, "tcp", 1),
            mapping("", 2000, 3000, "udp", 11),
        ]);
        let dns = vec![];
        let setup = PortForwardConfig {
            container_id: "0123456789abcdef".into(),
            network_id: "id".into(),
            port_mappings: &mappings,
            network_name: "nvtest".into(),
            network_hash_name: "hash".into(),
            container_ip_v4: Some("10.89.0.2".parse().unwrap()),
            subnet_v4: Some("10.89.0.0/24".parse().unwrap()),
            container_ip_v6: Some("fd00:89::2".parse().unwrap()),
            subnet_v6: Some("fd00:89::/64".parse().unwrap()),
            dns_port: 53,
            dns_server_ips: &dns,
            internal: false,
            snat_all: true,
        };
        let bridge = |_: &IpNet| Some("nvtest0".to_string());
        let rules = container_rules(&setup, &bridge).unwrap();
        assert_eq!(
            rules,
            "rdr pass inet proto tcp from any to (self) port 18080 -> 10.89.0.2 port 8000\n\
             nat on nvtest0 inet proto tcp from any to 10.89.0.2 port 8000 -> (nvtest0)\n\
             rdr pass inet proto udp from any to (self) port 2000:2010 -> 10.89.0.2 port 3000:*\n\
             nat on nvtest0 inet proto udp from any to 10.89.0.2 port 3000:3010 -> (nvtest0)\n\
             rdr pass inet6 proto tcp from any to (self) port 18080 -> fd00:89::2 port 8000\n\
             nat on nvtest0 inet6 proto tcp from any to fd00:89::2 port 8000 -> (nvtest0)\n\
             rdr pass inet6 proto udp from any to (self) port 2000:2010 -> fd00:89::2 port 3000:*\n\
             nat on nvtest0 inet6 proto udp from any to fd00:89::2 port 3000:3010 -> (nvtest0)\n"
        );
    }
}
