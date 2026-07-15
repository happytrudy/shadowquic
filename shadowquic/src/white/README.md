# Source whitelist

Both ShadowQUIC and SunnyQUIC inbounds check the QUIC peer's source IP against
`source-whitelist.yaml` in the current working directory.
`SHADOWQUIC_SOURCE_WHITELIST` is an environment variable that can override the
path.

The file uses the Clash/Mihomo rule-provider payload format:

```yaml
payload:
  - "SRC-IP-CIDR,203.0.113.7/32"
  - "SRC-IP-CIDR,198.51.100.0/24"
  - "SRC-IP-CIDR,2001:db8::/32"
```

An empty whitelist contains exactly one line:

```yaml
payload:
```

Exact IPv4 and IPv6 addresses and CIDR networks are supported. A missing file
disables filtering and allows every source. An existing empty, unreadable, or
invalid file denies every source. Changes are loaded at runtime. Connections
whose source is removed are closed immediately.
