---
sidebar_position: 6
sidebar_label: "Trusted proxies"
---
# Trusted proxies

When AliasVault sits behind another reverse proxy (HAProxy, Traefik, Cloudflare, an upstream nginx, etc.), the built-in nginx reads the real client IP from the `X-Forwarded-For` header so that audit logs and the IP allowlist see the actual client rather than the upstream proxy.

To prevent header spoofing, nginx only honors `X-Forwarded-For` when the request comes from an explicitly trusted upstream. The `TRUSTED_PROXIES` environment variable controls that list.

## How it works

For every incoming request, nginx checks the direct peer's IP against `TRUSTED_PROXIES`:

- If the peer IP matches a trusted entry, nginx replaces `$remote_addr` with the value from `X-Forwarded-For`.
- If it doesn't match, the header is ignored and the direct peer IP is used.

`real_ip_recursive` is enabled, so when a chain of trusted proxies is configured nginx walks the `X-Forwarded-For` list right-to-left until it finds the first untrusted address.

## Options

Set `TRUSTED_PROXIES` in the `environment:` section of your `docker-compose.yml` to one of:

| Value | Effect |
|---|---|
| _empty_ (default) | Trust no upstream proxies. Use the direct peer IP. |
| Comma-separated list of CIDRs/IPs | Trust only the listed proxies. **Recommended** when you know your upstream proxy address(es). |
| `none` | Trust no upstream proxies. `X-Forwarded-For` is always ignored and the direct peer IP is logged. |

### Examples

```yaml
# ...
    environment:
      # Trust only a specific HAProxy at 10.0.1.5 and a /24 of internal proxies:
      TRUSTED_PROXIES: "10.0.1.5,192.168.10.0/24"
# ...
```

```yaml
# ...
    environment:
      # Disable X-Forwarded-For handling entirely:
      TRUSTED_PROXIES: "none"
# ...
```

## Apply the change

After updating `docker-compose.yml`, the container must be recreated for the new environment value to take effect:

```bash
docker compose down
docker compose up -d
```

## Why narrow this down

Private addresses are not automatically trusted. List only actual upstream proxies; other workloads on the same network must not be able to select the client IP used by rate limits and access rules.

## Application proxy peers

The API and admin app also validate their immediate socket peer before accepting forwarding headers. `TRUSTED_APP_PROXIES` accepts comma-separated IPs, CIDRs or operator-controlled DNS names; loopback is always trusted. The multi-container compose explicitly trusts the `reverse-proxy` service. All-in-one uses loopback. DNS results are refreshed every minute; a lookup failure fails closed.

When upgrading a custom deployment, set this to the actual nginx peer and set `TRUSTED_PROXIES` separately to any CDN or proxy upstream of nginx. Do not use entire private networks unless every host in that network is a trusted proxy.
