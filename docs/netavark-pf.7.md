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

pf must be enabled, and the host's `pf.conf` must declare two tables and include the Netavark anchors.
Rules in an anchor that name a table use the main ruleset's table of that name, which is why the tables are declared in `pf.conf`:

```
table <netavark-subnets> persist
table <netavark-isolated> persist

nat-anchor "netavark/*"
rdr-anchor "netavark/*"
anchor "netavark/*"
```

The tables go with the other table definitions, `nat-anchor` and `rdr-anchor` with the translation rules, and `anchor` with the filter rules.
Without these lines `pfctl` still accepts the rules, but pf never evaluates them: containers have no outbound NAT and published ports do not answer.

Netavark adds no `pass` rules for ordinary container traffic.
A ruleset that blocks by default must pass traffic to and from the container networks itself.
`rdr pass` only admits a redirected connection on its way in; it still has to leave through the bridge:

```
pass from <netavark-subnets>
pass to <netavark-subnets>
```

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

### Rules

Each network gets an anchor named after the network.
It holds the outbound NAT on the interface of the host's default route, and the isolation rules when the network is internal or has the `isolate` option.
Each container with published ports gets an anchor named after the network and the container ID.
It holds `rdr pass` rules that redirect the host ports to the container, and a NAT rule on the bridge so that the container itself and the host's loopback can reach the published ports.
When DNS is enabled, port 53 on the gateway is redirected to aardvark-dns.

The `netavark-subnets` table lists the subnets of every Netavark network, and `netavark-isolated` those of networks with `isolate` set.
Isolation matches the nftables driver: an isolated network cannot open connections to other Netavark networks (with `isolate=strict`, any of them; otherwise, the isolated ones).
Incoming traffic is not filtered, and redirected connections are admitted by `rdr pass` before any filter rule.
Internal networks reach only their gateway.

The anchors can be listed with:

```
# pfctl -s Anchors -a netavark
```

When a network is removed, its anchor is flushed but may stay listed, empty.
pf keeps a reference from it to the host table, and flushing the anchor or its tables does not remove it.
This is harmless.

### Reloading pf

Reloading the ruleset (`service pf reload`, `pfctl -f /etc/pf.conf`) keeps the rules in the Netavark anchors and the entries in the tables.
Flushing it (`service pf restart`, `pfctl -F all`) removes them, and running containers lose outbound NAT and their published ports until the rules are restored with:

```
# netavark firewall-reload
```

### Limitations

Port forwarding via the IPv6 localhost address (`::1`) is not supported, as on Linux.

## SEE ALSO

netavark(1), pf.conf(5), pfctl(8), containers.conf(5)

## Authors

Michael Johnson
