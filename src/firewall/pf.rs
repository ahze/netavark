//! pf firewall driver for FreeBSD.
//!
//! Rules live in anchors under `netavark/`, loaded with `pfctl -a <anchor>
//! -f -` and flushed with `pfctl -a <anchor> -F rules`, `-F nat`, and `-F Tables`.
//! The host's pf.conf has to include them:
//!
//! ```text
//! nat-anchor "netavark/*"
//! rdr-anchor "netavark/*"
//! anchor "netavark/*"
//! ```
//!
//! One anchor per network holds its outbound NAT, its isolation rules, and
//! when isolated its own `<isolated>` table listing the peer subnets it may
//! not reach; one anchor per network and container holds that container's
//! port redirects, bridge NAT rules, and outbound state rules for
//! redirected traffic (`tag netavark-rdr`) so replies pass `<isolated>`.
//! Because `<isolated>` is defined inside the network anchor rather than in
//! the main ruleset, rules and isolation tables survive `service pf reload`,
//! `service pf restart`, and `pfctl -F all && pfctl -f /etc/pf.conf`.

use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
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
/// Anchor-local table listing the peer subnets that this network may not reach.
const ISOLATED_TABLE: &str = "isolated";
/// Tag applied to port-forwarded connections so replies pass `<isolated>`.
const RDR_TAG: &str = "netavark-rdr";

pub struct Pf {
    config_dir: PathBuf,
}

pub fn new(config_dir: PathBuf) -> NetavarkResult<Box<dyn firewall::FirewallDriver>> {
    Ok(Box::new(Pf { config_dir }))
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
        let _lock = firewall::state::lock_pf(&self.config_dir)?;
        let mut all_networks = firewall::state::read_network_configs(&self.config_dir)?;
        all_networks.retain(|n| n.network_hash_name != network_setup.network_hash_name);
        all_networks.push(network_setup);
        let self_idx = all_networks.len() - 1;
        let self_net = &all_networks[self_idx];

        let mut to_load: Vec<&SetupNetwork> = Vec::with_capacity(all_networks.len());
        to_load.push(self_net);
        if has_subnets(self_net) {
            for peer in &all_networks[..self_idx] {
                if peer_needs_reload(peer, self_net) {
                    to_load.push(peer);
                }
            }
        }

        let egress = if to_load.iter().any(|n| !n.internal && has_subnets(n)) {
            egress_interface()?
        } else {
            String::new()
        };

        for net in to_load {
            let rules = network_rules(net, &all_networks, &egress);
            load_anchor(&network_anchor(&net.network_hash_name), &rules)?;
        }
        Ok(())
    }

    fn teardown_network(&self, tear: TearDownNetwork) -> NetavarkResult<()> {
        if tear.complete_teardown {
            let _lock = firewall::state::lock_pf(&self.config_dir)?;
            let mut all_networks = firewall::state::read_network_configs(&self.config_dir)?;
            // A concurrent setup for the same network may have re-created its
            // network state file after remove_fw_config ran; leave the anchor alive.
            if all_networks
                .iter()
                .any(|n| n.network_hash_name == tear.config.network_hash_name)
            {
                return Ok(());
            }
            flush_anchor(&network_anchor(&tear.config.network_hash_name))?;
            if has_subnets(&tear.config) {
                all_networks.retain(|n| n.network_hash_name != tear.config.network_hash_name);
                let peers: Vec<&SetupNetwork> = all_networks
                    .iter()
                    .filter(|n| peer_needs_reload(n, &tear.config))
                    .collect();
                if !peers.is_empty() {
                    let egress = egress_interface()?;
                    for peer in peers {
                        let rules = network_rules(peer, &all_networks, &egress);
                        load_anchor(&network_anchor(&peer.network_hash_name), &rules)?;
                    }
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
        let _lock = firewall::state::lock_pf(&self.config_dir)?;
        let rules = container_rules(&setup_portfw, &interface_for_subnet)?;
        load_anchor(
            &container_anchor(&setup_portfw.network_hash_name, &setup_portfw.container_id),
            &rules,
        )
    }

    fn teardown_port_forward(&self, tear: TeardownPortForward) -> NetavarkResult<()> {
        let _lock = firewall::state::lock_pf(&self.config_dir)?;
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

fn has_subnets(network_setup: &SetupNetwork) -> bool {
    network_setup
        .subnets
        .as_ref()
        .is_some_and(|s| !s.is_empty())
}

/// Whether `peer`'s `<isolated>` table may include or drop `changed`'s subnets.
fn peer_needs_reload(peer: &SetupNetwork, changed: &SetupNetwork) -> bool {
    if peer.internal || !has_subnets(peer) {
        return false;
    }
    match peer.isolation {
        IsolateOption::Strict => true,
        IsolateOption::Normal => isolated(changed),
        IsolateOption::Never => false,
    }
}

/// Peer subnets that `network_setup` must block in its `<isolated>` table:
/// every other network's subnets under `strict`, or isolated peers under `normal`.
fn isolated_peers(network_setup: &SetupNetwork, all_networks: &[SetupNetwork]) -> Vec<IpNet> {
    let mut peers = Vec::new();
    for other in all_networks {
        if other.network_hash_name == network_setup.network_hash_name {
            continue;
        }
        let include = match network_setup.isolation {
            IsolateOption::Strict => true,
            IsolateOption::Normal => isolated(other),
            IsolateOption::Never => false,
        };
        if include {
            peers.extend(other.subnets.iter().flatten().copied());
        }
    }
    peers.sort();
    peers.dedup();
    peers
}

/// The rules of a network. When isolated, a `table <isolated>` definition
/// comes first (required before translation and filter rules by pf syntax),
/// followed by outbound NAT on `egress` (unless internal), and isolation
/// rules on the bridge.
fn network_rules(
    network_setup: &SetupNetwork,
    all_networks: &[SetupNetwork],
    egress: &str,
) -> String {
    if !has_subnets(network_setup) {
        return String::new();
    }
    let mut rules = String::new();
    let bridge = &network_setup.bridge_name;
    if !network_setup.internal && isolated(network_setup) {
        let peers = isolated_peers(network_setup, all_networks);
        if peers.is_empty() {
            rules.push_str(&format!("table <{ISOLATED_TABLE}> {{ }}\n"));
        } else {
            let addrs = peers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            rules.push_str(&format!("table <{ISOLATED_TABLE}> {{ {addrs} }}\n"));
        }
    }
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
        if !isolated(network_setup) {
            continue;
        }
        rules.push_str(&format!(
            "pass in quick on {bridge} {family} from {subnet} to {subnet}\n\
             pass in quick on {bridge} {family} from {subnet} to (self)\n\
             block in quick on {bridge} {family} from {subnet} to <{ISOLATED_TABLE}>\n"
        ));
    }
    rules
}

/// The rules of one container on one network: the DNS redirect when
/// aardvark-dns is not on port 53, and the port mappings. `bridge` names
/// the host interface of a subnet.
fn container_rules(
    setup_portfw: &PortForwardConfig,
    bridge: &dyn Fn(&IpNet) -> Option<String>,
) -> NetavarkResult<String> {
    let mut rules = String::new();
    let mut filter_rules = String::new();

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
            port_rules(
                &mut rules,
                &mut filter_rules,
                ip,
                subnet,
                setup_portfw,
                bridge,
            )?;
        }
        if let (Some(ip), Some(subnet)) = (setup_portfw.container_ip_v6, setup_portfw.subnet_v6) {
            port_rules(
                &mut rules,
                &mut filter_rules,
                ip,
                subnet,
                setup_portfw,
                bridge,
            )?;
        }
    }
    rules.push_str(&filter_rules);
    Ok(rules)
}

/// Redirects and bridge NAT for one address family of a container, plus an
/// outbound state rule on the bridge for redirected traffic (`tag netavark-rdr`)
/// so replies from the container pass peer `<isolated>` rules. NAT is limited
/// to loopback and the bridge's own subnet when this is the sole default route,
/// or widened to all sources when another network or `no_default_route` would
/// send replies elsewhere.
fn port_rules(
    rules: &mut String,
    filter_rules: &mut String,
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
    let mut emitted = false;

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
            emitted = true;
            rules.push_str(&format!(
                "rdr pass {family} proto {proto} from any to {host} port {host_ports} tag {RDR_TAG} -> {ip} port {container_ports}\n"
            ));
            rules.push_str(&format!(
                "nat on {bridge} {family} proto {proto} from {nat_src} to {ip} port {} -> ({bridge})\n",
                port_range(port.container_port, port.range)
            ));
        }
    }
    if emitted {
        // rdr pass skips filter evaluation only on entry; without an outbound
        // state on the target bridge, isolated peer bridges drop the reply.
        filter_rules.push_str(&format!(
            "pass out quick on {bridge} {family} from any to {ip} tagged {RDR_TAG}\n"
        ));
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

fn anchor_has_tables(anchor: &str) -> bool {
    let out = Command::new("pfctl")
        .args(["-q", "-a", anchor, "-s", "Tables"])
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(out) if out.status.success() => !String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        _ => false,
    }
}

fn flush_anchor(anchor: &str) -> NetavarkResult<()> {
    if !anchor_exists(anchor) {
        debug!("pf anchor {anchor} does not exist, nothing to flush");
        return Ok(());
    }
    debug!("flushing pf anchor {anchor}");
    // Only the anchor's own rule sets (and any anchor-local tables).
    // `-F all` would also flush the global state table and fail on the
    // parts an anchor does not have, while `-F Tables` errors when an
    // anchor never defined a table.
    let mut parts = vec!["rules", "nat"];
    if anchor_has_tables(anchor) {
        parts.push("Tables");
    }
    for what in parts {
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

    fn net(
        name: &str,
        subnets: Vec<&str>,
        isolation: IsolateOption,
        internal: bool,
    ) -> SetupNetwork {
        SetupNetwork {
            subnets: Some(subnets.into_iter().map(|s| s.parse().unwrap()).collect()),
            bridge_name: format!("br_{name}"),
            network_id: format!("id_{name}"),
            network_hash_name: format!("hash_{name}"),
            isolation,
            dns_port: 53,
            internal,
            dns_enabled: true,
            outbound_addr4: None,
            outbound_addr6: None,
        }
    }

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
            network_rules(&setup, std::slice::from_ref(&setup), "re0"),
            "nat on re0 inet from 10.89.0.0/24 to any -> (re0)\n\
             nat on re0 inet6 from fd00:89::/64 to !ff00::/8 -> (re0)\n"
        );
        let setup = SetupNetwork {
            outbound_addr4: Some(Ipv4Addr::new(192, 168, 86, 5)),
            subnets: Some(vec!["10.89.0.0/24".parse().unwrap()]),
            ..setup
        };
        assert_eq!(
            network_rules(&setup, std::slice::from_ref(&setup), "re0"),
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
            network_rules(&setup, std::slice::from_ref(&setup), "re0"),
            "table <isolated> { }\n\
             nat on re0 inet from 10.89.0.0/24 to any -> (re0)\n\
             pass in quick on nvtest0 inet from 10.89.0.0/24 to 10.89.0.0/24\n\
             pass in quick on nvtest0 inet from 10.89.0.0/24 to (self)\n\
             block in quick on nvtest0 inet from 10.89.0.0/24 to <isolated>\n"
        );
        let setup = SetupNetwork {
            isolation: IsolateOption::Normal,
            ..setup
        };
        assert_eq!(
            network_rules(&setup, std::slice::from_ref(&setup), "re0"),
            "table <isolated> { }\n\
             nat on re0 inet from 10.89.0.0/24 to any -> (re0)\n\
             pass in quick on nvtest0 inet from 10.89.0.0/24 to 10.89.0.0/24\n\
             pass in quick on nvtest0 inet from 10.89.0.0/24 to (self)\n\
             block in quick on nvtest0 inet from 10.89.0.0/24 to <isolated>\n"
        );
        let setup = SetupNetwork {
            internal: true,
            ..setup
        };
        assert_eq!(
            network_rules(&setup, std::slice::from_ref(&setup), "re0"),
            "pass in quick on nvtest0 inet from 10.89.0.0/24 to (nvtest0)\n\
             block in quick on nvtest0 inet from 10.89.0.0/24 to any\n"
        );
    }

    #[test]
    fn isolation_peer_tables() {
        let all = vec![
            net(
                "strict_a",
                vec!["10.89.1.0/24", "fd00:1::/64"],
                IsolateOption::Strict,
                false,
            ),
            net(
                "strict_b",
                vec!["10.89.2.0/24"],
                IsolateOption::Strict,
                false,
            ),
            net(
                "normal",
                vec!["10.89.3.0/24", "fd00:3::/64"],
                IsolateOption::Normal,
                false,
            ),
            net("open", vec!["10.89.4.0/24"], IsolateOption::Never, false),
            net("int", vec!["10.89.5.0/24"], IsolateOption::Strict, true),
        ];

        assert_eq!(
            network_rules(&all[0], &all, "re0"),
            "table <isolated> { 10.89.2.0/24, 10.89.3.0/24, 10.89.4.0/24, 10.89.5.0/24, fd00:3::/64 }\n\
             nat on re0 inet from 10.89.1.0/24 to any -> (re0)\n\
             nat on re0 inet6 from fd00:1::/64 to !ff00::/8 -> (re0)\n\
             pass in quick on br_strict_a inet from 10.89.1.0/24 to 10.89.1.0/24\n\
             pass in quick on br_strict_a inet from 10.89.1.0/24 to (self)\n\
             block in quick on br_strict_a inet from 10.89.1.0/24 to <isolated>\n\
             pass in quick on br_strict_a inet6 from fd00:1::/64 to fd00:1::/64\n\
             pass in quick on br_strict_a inet6 from fd00:1::/64 to (self)\n\
             block in quick on br_strict_a inet6 from fd00:1::/64 to <isolated>\n"
        );

        let normal_rules = network_rules(&all[2], &all, "re0");
        assert!(
            normal_rules.starts_with(
                "table <isolated> { 10.89.1.0/24, 10.89.2.0/24, 10.89.5.0/24, fd00:1::/64 }\n"
            ),
            "unexpected normal rules:\n{normal_rules}"
        );
        assert!(
            !normal_rules.contains("10.89.4.0/24"),
            "normal must not block non-isolated peer:\n{normal_rules}"
        );

        assert!(!peer_needs_reload(&all[2], &all[3]));
        assert!(peer_needs_reload(&all[0], &all[3]));
        assert!(peer_needs_reload(&all[2], &all[1]));
        assert!(!peer_needs_reload(&all[3], &all[0]));
        assert!(!peer_needs_reload(&all[4], &all[0]));
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
             rdr pass inet proto tcp from any to (self) port 18080 tag netavark-rdr -> 10.89.0.2 port 8000\n\
             nat on nvtest0 inet proto tcp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 8000 -> (nvtest0)\n\
             rdr pass inet proto udp from any to 192.168.86.5 port 2000:2010 tag netavark-rdr -> 10.89.0.2 port 3000:*\n\
             nat on nvtest0 inet proto udp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 3000:3010 -> (nvtest0)\n\
             rdr pass inet proto tcp from any to 192.168.86.5 port 2000:2010 tag netavark-rdr -> 10.89.0.2 port 3000:*\n\
             nat on nvtest0 inet proto tcp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 3000:3010 -> (nvtest0)\n\
             pass out quick on nvtest0 inet from any to 10.89.0.2 tagged netavark-rdr\n"
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
            "rdr pass inet proto tcp from any to (self) port 18080 tag netavark-rdr -> 10.89.0.2 port 8000\n\
             nat on nvtest0 inet proto tcp from any to 10.89.0.2 port 8000 -> (nvtest0)\n\
             rdr pass inet proto udp from any to (self) port 2000:2010 tag netavark-rdr -> 10.89.0.2 port 3000:*\n\
             nat on nvtest0 inet proto udp from any to 10.89.0.2 port 3000:3010 -> (nvtest0)\n\
             rdr pass inet6 proto tcp from any to (self) port 18080 tag netavark-rdr -> fd00:89::2 port 8000\n\
             nat on nvtest0 inet6 proto tcp from any to fd00:89::2 port 8000 -> (nvtest0)\n\
             rdr pass inet6 proto udp from any to (self) port 2000:2010 tag netavark-rdr -> fd00:89::2 port 3000:*\n\
             nat on nvtest0 inet6 proto udp from any to fd00:89::2 port 3000:3010 -> (nvtest0)\n\
             pass out quick on nvtest0 inet from any to 10.89.0.2 tagged netavark-rdr\n\
             pass out quick on nvtest0 inet6 from any to fd00:89::2 tagged netavark-rdr\n"
        );
    }

    #[test]
    fn container_port_rules_dual_stack_v4_only_mapping() {
        let mappings = Some(vec![mapping("127.0.0.1", 18080, 8000, "tcp", 1)]);
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
            snat_all: false,
        };
        let bridge = |_: &IpNet| Some("nvtest0".to_string());
        let rules = container_rules(&setup, &bridge).unwrap();
        assert_eq!(
            rules,
            "rdr pass inet proto tcp from any to 127.0.0.1 port 18080 tag netavark-rdr -> 10.89.0.2 port 8000\n\
             nat on nvtest0 inet proto tcp from { (lo0), 10.89.0.0/24 } to 10.89.0.2 port 8000 -> (nvtest0)\n\
             pass out quick on nvtest0 inet from any to 10.89.0.2 tagged netavark-rdr\n"
        );
    }
}
