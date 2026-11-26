% NETAVARK-PF 7 Netavark pf Interactions Man Page
% Michael Johnson
% November 2026

## Name

netavark-pf - description of the interaction of Netavark and pf on FreeBSD

## Description

On FreeBSD, Netavark uses the `pf` firewall driver by default.
It can also be selected by setting `firewall_driver` to `pf` in `containers.conf`, or with the `NETAVARK_FW` environment variable.
The driver runs `pfctl` and keeps every rule it adds in anchors under `netavark/`.
It never edits the host's `pf.conf` or loads the main ruleset.

### Host Configuration

pf must be enabled, and the host's `pf.conf` must include the Netavark anchors:

```
nat-anchor "netavark/*"
rdr-anchor "netavark/*"
anchor "netavark/*"
```

`nat-anchor` and `rdr-anchor` go with the translation rules, and `anchor` goes with the filter rules.
Without these lines `pfctl` still accepts the rules, but pf never evaluates them: containers have no outbound NAT, no isolation, and published ports do not answer.
The older root-ruleset `table <netavark-subnets> persist` and `table <netavark-isolated> persist` declarations are no longer needed; keeping them in an existing `pf.conf` is harmless, though Netavark leaves them empty.

Netavark adds no general `pass` rules for ordinary container traffic.
A ruleset that blocks by default must pass traffic to and from the container bridges or subnets itself (for example `pass on podman0`, or `pass from 10.88.0.0/16` and `pass to 10.88.0.0/16`).
For published ports, `rdr pass` admits redirected connections on entry with `tag netavark-rdr` and a `pass out quick` rule on the destination bridge creates outbound state so redirected traffic reaches the container and replies pass `<isolated>`.

To reach published ports through the host's own addresses, including `127.0.0.1`, set `net.pf.filter_local` before pf is enabled:

```
# sysctl net.pf.filter_local=1
# echo net.pf.filter_local=1 >> /etc/sysctl.conf
# sysrc -f /boot/loader.conf pf_load=YES
```

The setting only takes effect when pf is enabled after it.
At boot, `/etc/sysctl.conf` is applied before the pf module is loaded unless the loader loads it, which is what `pf_load=YES` does.
If pf is already running, disable and enable it again after changing the setting (`pfctl -d; pfctl -e`).
Without it, connections from the host to a published port on a local address time out, while connections from other hosts work.

Netavark enables IP forwarding (`net.inet.ip.forwarding`, and `net.inet6.ip6.forwarding` for IPv6 networks) when it sets up a network.

`aardvark-dns` binds port 53 on each network's gateway address.
If a resolver on the host is bound to `*:53` (for example `dnsmasq` or `unbound`), `aardvark-dns` fails to bind (`Address already in use`) and podman reports `"aardvark-dns failed to start"`.
Setting `dns_bind_port` under `[network]` in `containers.conf` moves `aardvark-dns` to that port and the `pf` driver redirects each network gateway's port 53 to it.
Set `dns_bind_port` before starting containers; if it is changed while containers are running, stop `aardvark-dns` and restart the containers that use DNS.

`aardvark-dns` 2.1.0 requires inotify (`vfs.inotify.max_user_instances` must be `0` or higher, default `256`).

### Rules

Each network gets an anchor named after the network (`netavark/<hash>`).
It holds the outbound NAT on the interface of the host's default route, and the isolation rules when the network is internal or has the `isolate` option.
Each container with published ports gets an anchor named after the network and the container ID (`netavark/<hash>-<id>`).
It holds `rdr pass ... tag netavark-rdr` rules that redirect the host ports to the container, a NAT rule on the bridge so that the container itself and the host's loopback can reach the published ports (widened to all sources when the container has additional networks or `no_default_route`, so replies return through the bridge), and a `pass out quick` rule on the bridge matching `tagged netavark-rdr` so outbound bridge state permits replies from isolated networks.
When DNS is enabled, port 53 on the gateway is redirected to aardvark-dns.

Each isolated network anchor carries its own `table <isolated>` listing the subnets of the peer Netavark networks it may not reach (`isolate=strict` lists every other Netavark subnet; `isolate=true` lists the subnets of other isolated networks).
Netavark updates the `<isolated>` tables across active network anchors whenever a network is set up or torn down.
Isolation matches the nftables driver: an isolated network cannot open connections to other Netavark networks (with `isolate=strict`, any of them; otherwise, the isolated ones), while published ports remain reachable across networks because `rdr pass` sets `tag netavark-rdr` and the container anchor creates outbound state on the destination bridge.
Internal networks reach only their gateway.

The anchors can be listed with:

```
# pfctl -s Anchors -a netavark
```

When a network is removed, its rules, NAT rules, and `<isolated>` table are flushed, leaving the anchor empty (though pf still keeps empty sub-anchor entries listed until the host reboots).
This is harmless.

### Reloading pf

Reloading the ruleset (`service pf reload`, `pfctl -f /etc/pf.conf`), restarting pf (`service pf restart`), and flushing the main ruleset followed by reloading `pf.conf` (`pfctl -F all && pfctl -f /etc/pf.conf`) all keep the rules, NAT rules, and `<isolated>` tables inside the `netavark/*` sub-anchors in place, so outbound NAT, published ports, and network isolation keep working without running Netavark again.
A bare `pfctl -F all` without reloading `pf.conf` removes the `netavark/*` anchor hooks from the main ruleset until `pf.conf` is loaded again.
If the `netavark/*` sub-anchors themselves are flushed directly, restore the rules and tables of running containers from Netavark's firewall state with:

```
# netavark firewall-reload
```

### Limitations

Port forwarding via the IPv6 localhost address (`::1`) is not supported, as on Linux.

## SEE ALSO

netavark(1), pf.conf(5), pfctl(8), containers.conf(5)

## Authors

Michael Johnson
