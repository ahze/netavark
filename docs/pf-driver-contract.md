# Netavark FreeBSD `pf` Driver Contract

Specification of every `pfctl` invocation, anchor, table, emitted rule, event sequence, and required `pf` library operation in [src/firewall/pf.rs](../src/firewall/pf.rs).

Any FreeBSD kernel or `pf` runtime behavior not directly visible in Netavark's Rust source is explicitly marked `[inferred / pf kernel behavior]` or `[observed on FreeBSD 15.1]`.

---

## 1. Driver Role & Host `pf.conf` Contract

Netavark's `Pf` struct ([src/firewall/pf.rs#L47-L146](../src/firewall/pf.rs#L47-L146)) implements the `FirewallDriver` trait ([src/firewall/mod.rs#L30-L51](../src/firewall/mod.rs#L30-L51)), storing `config_dir` so it can read peer network definitions from disk and serialize PF updates across concurrent Netavark processes via `pf.lock`. It never edits `/etc/pf.conf` and never replaces the main ruleset ([docs/netavark-pf.7.md#L11-L32](netavark-pf.7.md#L11-L32)).

The host's `/etc/pf.conf` only needs to include the three wildcard anchor attachment points ([src/firewall/pf.rs#L5-L20](../src/firewall/pf.rs#L5-L20)):

```pf
nat-anchor "netavark/*"
rdr-anchor "netavark/*"
anchor "netavark/*"
```

No root-ruleset tables are created or queried by Netavark. Instead, each isolated network anchor (`netavark/{network_hash_name}`) defines its own anchor-local `table <isolated> { ... }`. Because both rules and `<isolated>` tables live inside `netavark/*` sub-anchors, network isolation survives `service pf reload`, `service pf restart`, and `pfctl -F all && pfctl -f /etc/pf.conf` without re-running Netavark (`[observed on FreeBSD 15.1]`). Older hosts or provisioning tools that still declare unused `table <netavark-subnets> persist` and `table <netavark-isolated> persist` lines in `/etc/pf.conf` remain compatible; Netavark simply leaves those root tables empty (`[observed on FreeBSD 15.1]`).

---

## 2. All `pfctl` Invocations in `src/firewall/pf.rs`

There are **4 `Command::new("pfctl")` call sites** in the entire repository, all in [src/firewall/pf.rs](../src/firewall/pf.rs):

| Function | Line | Exact `argv` | `stdin` | `stdout` / `stderr` | Behavior on Failure |
|---|---|---|---|---|---|
| `load_anchor` | [455-482](../src/firewall/pf.rs#L455-L482) | `pfctl -q -a <anchor> -f -` | `piped`: full UTF-8 table + rule string `rules.as_bytes()`, then EOF | `null` / `piped` | Returns `Err("pfctl -a <anchor> -f: <stderr>")` on non-zero exit |
| `anchor_exists` | [487-499](../src/firewall/pf.rs#L487-L499) | `pfctl -q -s Anchors -a netavark` | None | `piped` / `null` | Never errors; returns `true` iff exit `0` and any trimmed output line equals `anchor` |
| `anchor_has_tables` | [501-510](../src/firewall/pf.rs#L501-L510) | `pfctl -q -a <anchor> -s Tables` | None | `piped` / `null` | Never errors; returns `true` iff exit `0` and trimmed stdout is non-empty |
| `flush_anchor` | [512-543](../src/firewall/pf.rs#L512-L543) | 1. `pfctl -q -a <anchor> -F rules`<br>2. `pfctl -q -a <anchor> -F nat`<br>3. `pfctl -q -a <anchor> -F Tables` (only if `anchor_has_tables`) | None | `null` / `piped` | Short-circuits `Ok(())` if `anchor_exists` is `false`; otherwise returns `Err` on first non-zero exit |

### Invocation Details

1. **`load_anchor(anchor, rules)` (`pf.rs:455-482`):**
   - Atomically replaces all anchor-local tables, translation (`nat`/`rdr`) rules, and filter (`pass`/`block`) rules defined by `rules` inside `<anchor>` (`pfctl -q -a <anchor> -f -`).
   - `rules` can be empty (`""`): for instance when `SetupNetwork.subnets` is `None` or empty (`pf.rs:205-207`), or when a container has `dns_port == 53` and either `internal == true` or `port_mappings` is `None`/`Some([])` (`pf.rs:276-317`). In those cases `load_anchor` still spawns `pfctl` with empty `stdin`, creating or clearing the anchor to 0 rules.
   - When multiple network anchors define `table <isolated> { ... }`, FreeBSD `pfctl` prints `pfctl: warning: table <isolated> already defined in anchor "netavark/..."` to `stderr` while exiting `0` (`[observed on FreeBSD 15.1]`). `load_anchor` captures `stderr` via `Stdio::piped()` and treats exit `0` as success; kernel-side each anchor maintains an independent `<isolated>` address table.
   - Redefining `table <isolated> { ... }` inside the same anchor via `pfctl -q -a <anchor> -f -` replaces the table's address set (including shrinking from non-empty to `{ }`) atomically with the ruleset (`[observed on FreeBSD 15.1]`).

2. **`anchor_exists(anchor)`, `anchor_has_tables(anchor)`, and `flush_anchor(anchor)` (`pf.rs:487-543`):**
   - `flush_anchor` checks `pfctl -q -s Anchors -a netavark` first because `pfctl -a <anchor> -F ...` fails if `<anchor>` was never created (such as during setup rollback after an early failure, `pf.rs:484-486`).
   - When present, `flush_anchor` flushes `"rules"` and `"nat"`, and additionally flushes `"Tables"` only when `anchor_has_tables(anchor)` is `true`. It avoids `-F all` (`pf.rs:519-521`) so it does not flush the global state table or fail on rule parts an anchor does not carry; similarly it checks `anchor_has_tables` because `pfctl -a <anchor> -F Tables` exits non-zero (`Operation not supported by device`) on container anchors that never defined a table, whereas flushing only `rules` and `nat` leaves an anchor-local `table <isolated>` populated in kernel memory (`[observed on FreeBSD 15.1]`).
   - Note on empty anchors (`netavark-pf.7.md#L75-L76`): after flushing `rules`, `nat`, and `Tables`, the empty anchor name may remain listed in `pfctl -s Anchors -a netavark` until host reboot (`[observed on FreeBSD 15.1]`). Its rule, NAT, and table sets are empty and Netavark treats this as harmless.

---

## 3. Tables & Anchors Created and Their Names

| Object | Kind | Exact Name / Pattern | Source | Lifecycle |
|---|---|---|---|---|
| Network anchor | Level-1 anchor | `netavark/{network_hash_name}` | [pf.rs#L41](../src/firewall/pf.rs#L41), [pf.rs#L406-L408](../src/firewall/pf.rs#L406-L408) | Replaced on `setup_network` and when a peer network changes isolation membership; flushed on `complete_teardown` |
| Peer block table | Anchor-local table (inside `netavark/{network_hash_name}`) | `isolated` | [pf.rs#L43](../src/firewall/pf.rs#L43), [pf.rs#L210-L222](../src/firewall/pf.rs#L210-L222) | Defined and populated atomically in `load_anchor` when `!internal` and `isolation` is `Normal` or `Strict`; cleared with `-F Tables` on `complete_teardown` |
| Container anchor | Level-1 anchor | `netavark/{network_hash_name}-{id12}` | [pf.rs#L410-L413](../src/firewall/pf.rs#L410-L413) | Replaced on `setup_port_forward`; flushed on every container `teardown_port_forward` |

Where:
- `network_hash_name`: first `MAX_HASH_SIZE` (`13`, [src/firewall/mod.rs#L21](../src/firewall/mod.rs#L21)) uppercase hex characters of `SHA-512(network.name.as_bytes())` ([src/network/core_utils.rs#L289-L295](../src/network/core_utils.rs#L289-L295), called from [src/network/bridge.rs#L592-L593](../src/network/bridge.rs#L592-L593)).
- `{id12}`: `&container_id[..12]` when `container_id.len() >= 12`, else full `container_id` (`container_id.get(..12).unwrap_or(container_id)`, `pf.rs:411`).
- Both network and container anchors live at depth 1 directly under `netavark/` (separated by `-` rather than `/`) so single-level wildcard anchors (`"netavark/*"`) match both.

Note on isolation defaults ([src/network/bridge.rs#L1506-L1523](../src/network/bridge.rs#L1506-L1523)):
- If the network `"isolate"` option is omitted, Netavark defaults to `IsolateOption::Strict`.
- `"strict"` -> `IsolateOption::Strict`; `"true"` -> `IsolateOption::Normal`; `"false"` -> `IsolateOption::Never`.

---

## 4. Every Emitted Rule Shape

### 4.1 Network Anchor Rules (`network_rules`, `pf.rs:200-271`)

`egress` is resolved once per `setup_network` / `teardown_network` batch (when at least one loaded network has `!internal` and non-empty `subnets`) via netlink `get_default_route_interface(&mut host, None)` ([pf.rs#L417-L428](../src/firewall/pf.rs#L417-L428)). `bridge` is `network_setup.bridge_name` (e.g. `podman0`, `podman1`). `pf.conf` grammar requires ordering: `table` statements first, translation (`nat`) rules second, and filter (`pass`/`block`) rules third.

1. **Anchor-local isolation table** (when `!internal` and `isolation` is `Strict` or `Normal`, `pf.rs:176-222`):
   - Collects peer subnets from all other active networks in `all_networks` (`other.network_hash_name != network_setup.network_hash_name`):
     - Under `IsolateOption::Strict`: includes every other active network's subnets (regardless of peer `isolation` or `internal`).
     - Under `IsolateOption::Normal`: includes other active networks where `isolated(other)` (`Normal` or `Strict`).
   - Sorted canonically (`IpNet::Ord`: IPv4 ascending, then IPv6 ascending) and deduplicated:
     ```pf
     table <isolated> { 10.89.2.0/24, fd00:2::/64 }
     ```
   - Empty inline table when no matching peer subnets exist:
     ```pf
     table <isolated> { }
     ```
2. **IPv4 outbound NAT** (per IPv4 `subnet` in `subnets` when `!internal`, `pf.rs:223-236`):
   - Dynamic interface target (`outbound_addr4 == None`):
     ```pf
     nat on {egress} inet from {subnet} to any -> ({egress})
     ```
   - Explicit source address (`outbound_addr4 == Some(addr4)`):
     ```pf
     nat on {egress} inet from {subnet} to any -> {addr4}
     ```
3. **IPv6 outbound NAT** (per IPv6 `subnet` in `subnets` when `!internal`, `pf.rs:237-246`; excludes multicast `ff00::/8`):
   - Dynamic interface target (`outbound_addr6 == None`):
     ```pf
     nat on {egress} inet6 from {subnet} to !ff00::/8 -> ({egress})
     ```
   - Explicit source address (`outbound_addr6 == Some(addr6)`):
     ```pf
     nat on {egress} inet6 from {subnet} to !ff00::/8 -> {addr6}
     ```
4. **Internal network isolation** (per `subnet`, `family` in `{"inet", "inet6"}`, when `internal == true`, `pf.rs:248-260`):
   ```pf
   pass in quick on {bridge} {family} from {subnet} to ({bridge})
   block in quick on {bridge} {family} from {subnet} to any
   ```
   Allows gateway traffic (including `aardvark-dns`) to the bridge's own address while blocking all routed/forwarded egress from `{bridge}`.
5. **Cross-network isolation** (per `subnet`, `family` in `{"inet", "inet6"}`, when `!internal` and `isolation` != `IsolateOption::Never`, `pf.rs:261-268`):
   ```pf
   pass in quick on {bridge} {family} from {subnet} to {subnet}
   pass in quick on {bridge} {family} from {subnet} to (self)
   block in quick on {bridge} {family} from {subnet} to <isolated>
   ```

### 4.2 Container Anchor Rules (`container_rules` + `port_rules`, `pf.rs:276-404`)

`container_rules` emits all translation rules first (optional DNS redirects, followed by per-family `rdr` + `nat` pairs for `container_ip_v4`/`subnet_v4` and `container_ip_v6`/`subnet_v6` when `!internal`), and appends accumulated `filter_rules` (`pass out quick`) after both families so dual-stack anchors preserve PF's strict translation-before-filter rule ordering (`pf.rs:280-315`). For each subnet, `interface_for_subnet(&subnet)` (`pf.rs:431-453`) walks `nix::ifaddrs::getifaddrs()` to find the host bridge interface holding an address in `subnet` (returning `Err` if none exists).

6. **DNS non-53 port redirect** (when `dns_port != 53`, for every `ip` in `dns_server_ips`, emitted **even when `internal == true`**, `pf.rs:283-291`):
   ```pf
   rdr pass {family} proto { tcp, udp } from any to {ip} port 53 -> {ip} port {dns_port}
   ```
7. **Published port redirect, single port** (`!internal`, `port.range <= 1`, per comma-trimmed non-empty `proto` in `port.protocol`, `pf.rs:344-368`):
   ```pf
   rdr pass {family} proto {proto} from any to {host} port {host_port} tag netavark-rdr -> {ip} port {container_port}
   ```
   - `host` comes from `host_address(port, is_v4)` (`pf.rs:382-396`): `"(self)"` when `host_ip` is `""`, `"0.0.0.0"`, or `"::"`; otherwise the parsed `IpAddr` string if its address family matches `ip.is_ipv4()`, or skipped (`None`) if mismatched (e.g. `host_ip = "::1"` skips IPv4 port rules and `host_ip = "127.0.0.1"` skips IPv6 port rules).
   - Tags redirected connections with `RDR_TAG` (`netavark-rdr`, `pf.rs:45`).
8. **Published port redirect, port range** (`!internal`, `port.range > 1`, `host_end = port.host_port + port.range - 1`, `pf.rs:348-368, 398-404`):
   ```pf
   rdr pass {family} proto {proto} from any to {host} port {host_port}:{host_end} tag netavark-rdr -> {ip} port {container_port}:*
   ```
   (`pf` preserves the `1:1` port offset across `{container_port}:*`, `[inferred / pf.conf syntax]`).
9. **Published port bridge hairpin NAT (bridge-only container with default route on bridge)** (`!internal`, `snat_all == false`, `pf.rs:337-341, 363-366`):
   - `container_ports` is `container_port` if `range <= 1`, or `{container_port}:{container_port + range - 1}` if `range > 1`.
   ```pf
   nat on {bridge} {family} proto {proto} from { (lo0), {subnet} } to {ip} port {container_ports} -> ({bridge})
   ```
   Preserves real client source IPs for off-host clients, non-loopback host IPs, and permitted peers on other bridges while NATting loopback and same-subnet hairpin connections.
10. **Published port full bridge SNAT (`snat_all == true`)** (`!internal`, when `multi_network || no_default_route`, `pf.rs:337-341, 363-366`, [setup.rs#L99](../src/commands/setup.rs#L99), [bridge.rs#L717](../src/network/bridge.rs#L717)):
    ```pf
    nat on {bridge} {family} proto {proto} from any to {ip} port {container_ports} -> ({bridge})
    ```
    Rewrites source addresses of **all** forwarded connections on `{bridge}` (including off-host, host LAN IP, and other-bridge peers) to the bridge's host gateway address so replies return over `{bridge}` and match `pf`'s `rdr` state even when the container sends default traffic out a LAN interface or has `no_default_route=true`.
11. **Redirected traffic outbound bridge state** (per address family when at least one port mapping rule was emitted for that family, `pf.rs:369-375`):
    ```pf
    pass out quick on {bridge} {family} from any to {ip} tagged netavark-rdr
    ```
    `rdr pass` creates an inbound (`PF_IN`) state only on entry; without an outbound state on `{bridge}`, replies from `{ip}` toward a peer isolated bridge do not match the inbound `rdr` state when entering `{bridge}` and are dropped by `block in quick on {bridge} ... to <isolated>` (`[observed on FreeBSD 15.1]`). Matching `tagged netavark-rdr` on `out on {bridge}` creates outbound state on `{bridge}` so return packets match before `<isolated>` is evaluated while keeping unsolicited traffic between isolated networks blocked.

Note: Inside `container_rules`, translation rules (`rdr` + `nat`) precede filter rules (`pass out quick`); on dual-stack containers all IPv4 and IPv6 translation rules emit before both `pass out quick` lines (`pf.rs:280-315`). PF implicitly applies `keep state` on `pass`, `rdr pass`, and `nat` rules (`[inferred / pfctl default keep state]`).

---

## 5. Operation Sequence & Concurrency Controls per Netavark Event

Notice first which drivers invoke `Pf`:
- **Managed `Bridge` (`mode=managed`, the default for `bridge` networks):** invokes `Pf` ([src/network/bridge.rs#L433-L438](../src/network/bridge.rs#L433-L438), [#L545-L551](../src/network/bridge.rs#L545-L551)).
- **Unmanaged `Bridge` (`mode=unmanaged`), `Vlan` (`macvlan`/`ipvlan`), and external plugins (`PluginDriver`, such as `epair`):** make **zero** calls to `Pf` or `write_fw_config` ([bridge.rs#L433](../src/network/bridge.rs#L433), [vlan.rs](../src/network/vlan.rs), [plugin.rs](../src/network/plugin.rs)).

Peer network state and lock hierarchy ([src/firewall/state.rs](../src/firewall/state.rs)):
- `write_fw_config` ([state.rs#L130-L172](../src/firewall/state.rs#L130-L172)) writes `$config/firewall/networks/{net_id}` atomically via `.{net_id}.tmp` + `rename` while holding `firewall-reload.lock`.
- `read_dir_conf` ([state.rs#L272-L296](../src/firewall/state.rs#L272-L296)) skips dotfiles (`.tmp` staging files).
- `read_network_configs` ([state.rs#L263-L270](../src/firewall/state.rs#L263-L270)) reads `$config/firewall/networks/*` **without** locking `firewall-reload.lock`, because `netavark firewall-reload` holds `firewall-reload.lock` across its calls to `Pf::setup_network` ([firewall_reload.rs#L37-L51](../src/commands/firewall_reload.rs#L37-L51)) and would deadlock if `Pf` tried to re-acquire `firewall-reload.lock`.
- `lock_pf` ([state.rs#L239-L258](../src/firewall/state.rs#L239-L258)) exclusively locks `$config/firewall/pf.lock` inside every `Pf` method (`setup_network`, `teardown_network`, `setup_port_forward`, `teardown_port_forward`). Because `firewall-reload` acquires `firewall-reload.lock` outside `setup_network`, and `write_fw_config` / `remove_fw_config` / `enable_container_port_snat` hold `firewall-reload.lock` without nesting `Pf` (except `enable_container_port_snat`, which calls `setup_port_forward` while holding `firewall-reload.lock`), the global lock order is strictly `firewall-reload.lock -> pf.lock` with zero lock inversions. `pf.lock` serializes peer snapshots against anchor `pfctl` writes across concurrent container starts, teardowns, and `firewall-reload`.

In [src/commands/setup.rs#L80-L99](../src/commands/setup.rs#L80-L99), `existing_ifaces` counts container interfaces that are both `LinkFlags::Up` and `!LinkFlags::Loopback`, so unconfigured kernel VNET pseudo-interfaces (such as `pflog0` when `pflog.ko` is loaded) do not falsely trigger `multi_network = true` and `snat_all = true` on single-network containers (`[observed on FreeBSD 15.1]`).

| Event | Call Path | Exact Order of `pf` / `pfctl` Operations |
|---|---|---|
| **`network create`** | [src/commands/create.rs#L10-L22](../src/commands/create.rs#L10-L22) | **None.** Generates JSON config only. |
| **`network remove`** | [src/main.rs#L44-L65](../src/main.rs#L44-L65) | **None.** Netavark has no `network remove` subcommand; host bridge & network PF state remain until the last container tears down. |
| **`container setup`** (and **`port publish`**) | [setup.rs#L51-L176](../src/commands/setup.rs#L51-L176), [bridge.rs#L709-L737](../src/network/bridge.rs#L709-L737) | 1. For each attached network in slice order (`drivers`): non-managed drivers run no PF ops. Each Managed `Bridge` runs:<br>  a. `write_fw_config` atomically writes `$config/firewall/{firewall-driver,networks/<net_id>,ports/<net_id>_<cid>}` (`!rootless`) under `firewall-reload.lock`.<br>  b. `Pf::setup_network`: acquires `pf.lock`; reads `read_network_configs(&self.config_dir)` + upserts `network_setup`; determines affected peers via `peer_needs_reload` (`Strict` peers always, `Normal` peers when `isolated(&network_setup)`); calls `egress_interface()` once if needed; runs `pfctl -q -a netavark/<hash> -f -` (`network_rules` including `table <isolated>`) on this network first, then on each affected existing peer network anchor; releases `pf.lock`.<br>  c. `Pf::setup_port_forward`: acquires `pf.lock`; `interface_for_subnet()` (ifaddrs) -> `pfctl -q -a netavark/<hash>-<cid12> -f -` (`container_rules` stdin, using `snat_all = multi_network \|\| no_default_route`); releases `pf.lock`.<br>2. On driver setup failure ([setup.rs#L145-L158](../src/commands/setup.rs#L145-L158), [bridge.rs#L245-L257](../src/network/bridge.rs#L245-L257)), Netavark runs teardown on this bridge and all earlier drivers to roll back PF anchors, peer tables, and interfaces. |
| **Live `network connect`** | [setup.rs#L80-L176](../src/commands/setup.rs#L80-L176), [state.rs#L300-L342](../src/firewall/state.rs#L300-L342) | Podman runs `netavark setup` for the newly added network only while `existing_ifaces >= 1` (`setup.rs:80-99`), setting `multi_network = true`.<br>1. If the new network is Managed `Bridge`, its `setup_firewall` runs with `snat_all = true`, loading its anchor and updating any affected peers' `<isolated>` tables.<br>2. After all drivers in this invocation succeed (`setup.rs:166-176`), on FreeBSD `!rootless && existing_ifaces > 0 && multi_network`: `enable_container_port_snat` scans `firewall/ports/*_<cid>`; for any existing bridge port file with `snat_all == false`, sets `snat_all = true`, rewrites the JSON file, and calls `Pf::setup_port_forward` -> `pfctl -q -a netavark/<hash>-<cid12> -f -` with `from any` under `pf.lock`. (On error, rolls back the newly added drivers.) |
| **`container teardown`** | [teardown.rs#L115-L162](../src/commands/teardown.rs#L115-L162), [bridge.rs#L490-L579, L739-L835](../src/network/bridge.rs#L739-L835) | Per Managed `Bridge` (`mode == Managed`), after `netns_teardown` and `destroy_orphaned_epairs`:<br>1. Determines `complete_teardown = bridge_members(&bridge_name)?.is_empty() && mode == Managed` (bridge still exists with its gateway IP here).<br>2. `remove_fw_config`: deletes `ports/<net_id>_<cid>`, and if `complete_teardown` deletes `networks/<net_id>` under `firewall-reload.lock`.<br>3. **If `complete_teardown`**, `Pf::teardown_network` runs **first** under `pf.lock`:<br>  a. Reads `read_network_configs(&self.config_dir)`; if a concurrent setup already re-created `networks/<net_id>`, returns `Ok(())` without flushing.<br>  b. `pfctl -q -s Anchors -a netavark`; if `netavark/<hash>` exists: `pfctl -q -a netavark/<hash> -F rules`, `pfctl -q -a netavark/<hash> -F nat`, then `pfctl -q -a netavark/<hash> -s Tables` and if non-empty `pfctl -q -a netavark/<hash> -F Tables`.<br>  c. If removed network had non-empty `subnets`: finds affected remaining peers (`peer_needs_reload`), calls `egress_interface()` once if non-empty, and reloads each affected peer's `netavark/<peer_hash>` anchor via `pfctl -q -a <peer> -f -` so the removed subnets leave every peer's `<isolated>` table.<br>4. **Always**, `Pf::teardown_port_forward` runs **second** under `pf.lock`:<br>  a. `pfctl -q -s Anchors -a netavark`; if `netavark/<hash>-<cid12>` exists: `pfctl -q -a netavark/<hash>-<cid12> -F rules`, `pfctl -q -a netavark/<hash>-<cid12> -F nat` (`-s Tables` is empty on container anchors, so `-F Tables` is skipped).<br>5. Finally (if `complete_teardown`), `host.del_link` destroys the bridge interface. |
| **Live `network disconnect`** | [teardown.rs#L115-L162](../src/commands/teardown.rs#L115-L162) | Podman runs `netavark teardown` with only the removed network (`container teardown` sequence runs for that single network; any remaining bridge keeps `snat_all = true` for the lifetime of the container). |
| **`firewall-reload`** | [firewall_reload.rs#L35-L56](../src/commands/firewall_reload.rs#L35-L56) | Acquires exclusive `firewall-reload.lock`, reads `firewall/firewall-driver` (returns `Ok(())` if missing):<br>1. For every stored `SetupNetwork` in `firewall/networks/*`: calls `Pf::setup_network` (which acquires `pf.lock`, reads `firewall/networks/*` lock-free, and restores each `netavark/<hash>` anchor and its `<isolated>` table).<br>2. For every stored `PortForwardConfigOwned` in `firewall/ports/*`: calls `Pf::setup_port_forward` under `pf.lock` (reloading `netavark/<hash>-<cid12>`, including persisted `snat_all`). |

---

## 6. Minimal Rust `pf` Library Operations Required

To replace all 4 `pfctl` subprocess call sites in [src/firewall/pf.rs](../src/firewall/pf.rs) without changing Netavark's behavior, a native `/dev/pf` (`ioctl` / `pfctl` netlink) Rust library needs only **2 operations** and a small rule AST:

### 6.1 Required Operations

1. **`replace_anchor_rules(anchor: &str, spec: AnchorSpec<'_>) -> Result<()>`**
   - Atomically replaces an optional anchor-local `table <isolated> { ... }` (when `Some(addrs: &[IpNet])`), all `nat` rules, all `rdr` rules, and all filter (`pass`/`block`) rules inside the named level-1 anchor (`"netavark/<hash>"` or `"netavark/<hash>-<cid12>"`).
   - Must succeed when all rule lists are empty (clearing the anchor to 0 rules, as happens for containers without port mappings when `dns_port == 53`, or networks with `subnets == None`).
   - When `table <isolated>` is supplied with an empty `&[]` address slice, the table must still exist inside `<anchor>` as an empty address table (matching `table <isolated> { }`); when an anchor's table is updated in place (e.g. a peer network added or removed), the new address list must replace the old entries atomically within the same commit so stale peer subnets never linger or disappear early.
   - Must work inside a transaction (`DIOCXBEGIN` / table replace / `DIOCADDRULE` / `DIOCXCOMMIT`, `[inferred / pf kernel behavior]`) so concurrent containers or `firewall-reload` do not see half-loaded rules or tables.
2. **`flush_anchor(anchor: &str) -> Result<()>`**
   - Clears filter (`pass`/`block`), `nat`, `rdr`, and any anchor-local tables (`isolated`) inside `"netavark/<hash>"` or `"netavark/<hash>-<cid12>"` **without** flushing the global state table.
   - Must treat a nonexistent anchor or an anchor with no tables as `Ok(())` (idempotent; eliminating the separate `anchor_exists` and `anchor_has_tables` queries).

Root-table add/delete operations (`table_add_addrs`, `table_del_addrs`) are **no longer needed** by Netavark.

### 6.2 Rule & Address Features Needed vs Not Needed

- **Rule actions required:**
  - `nat` (with source-pool / round-robin default matching `pfctl` NAT syntax)
  - `rdr pass` (sets the PF `pass` flag so matched packets skip anchor/root filter evaluation on ingress, with optional `tag <name>`, `[inferred / pf kernel behavior]`)
  - Filter `pass in quick`, `pass out quick`, and `block in quick` (with PF default state tracking enabled on `pass`, `[inferred / pfctl default keep state]`)
- **Fields & matchers required:**
  - `af`: `Inet` (IPv4) | `Inet6` (IPv6)
  - `ifname`: `Option<&str>` (`on {egress}` for NAT, `on {bridge}` for `in`/`out` filter and hairpin/SNAT `nat`; unset on `rdr pass`)
  - `proto`: `Option<Proto>` (`Tcp`, `Udp`, `Sctp` from `PortMapping.protocol`, multi-proto `{ tcp, udp }` for DNS redirect, or unset for network NAT/filter rules)
  - `tag` / `tagged`: `Option<&str>` (`tag netavark-rdr` on `rdr pass`, `tagged netavark-rdr` on `pass out quick`)
  - `src` / `dst` endpoints:
    - `Any` (`any`)
    - `Subnet { net: IpNet, negated: bool }` (`10.89.0.0/24`, `!ff00::/8`)
    - `Addr(IpAddr)` (`10.89.0.2`, `10.89.0.1`, `192.168.86.5`)
    - `DynIface(&str)` for `(self)`, `(lo0)`, `({egress})`, `({bridge})` (kernel resolves dynamic interface IP set, `[inferred / pf kernel behavior]`)
    - `Table(&str)` resolving the anchor-local `<isolated>` table defined in the same anchor
    - Or a small `Vec<Endpoint>` source list for `{ (lo0), {subnet} }` (or emit two NAT rules: one for `(lo0)` and one for `{subnet}`, which is equivalent if `(lo0)` and `{subnet}` are separate rules)
  - Destination ports on `rdr` / `nat`: `Single(u16)` or inclusive `Range(u16, u16)`
  - Translation targets:
    - `nat -> Addr(IpAddr) | DynIface(&str)`
    - `rdr -> (IpAddr, Single(u16) | PortRangeBase(u16))` (`port {container_port}:*` mapping host range `[host_port..host_port+range)` sequentially onto `[container_port..]`, `[inferred / pf kernel behavior]`)
- **Out of scope (not used by Netavark):**
  - Root-ruleset table mutations (`netavark-subnets`, `netavark-isolated`)
  - Parsing `/etc/pf.conf` text
  - Modifying the root ruleset's rules (`anchor` lines stay user-managed)
  - Multi-level nested anchors below `netavark/`
  - `scrub`, `altq`, `dummynet`, `route-to`, `binat`, `af-to`, `pfsync`, `pflog`, or reading PF state/rule counters
