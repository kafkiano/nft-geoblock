# nft-geoblock.sh

Load country IP blocks into an nftables verdict map to block (or allow) traffic by country.

## Usage

```bash
curl -fsSL https://raw.githubusercontent.com/kafkiano/nft-geoblock/main/nft-geoblock.sh | sudo bash -s -- [-n name] [-p ports] [-w] CC [CC ...]
```

## Install

```bash
curl -O https://raw.githubusercontent.com/kafkiano/nft-geoblock/main/nft-geoblock.sh
chmod +x nft-geoblock.sh
sudo ./nft-geoblock.sh [-n name] [-p ports] [-w] CC [CC ...]
```

| Flag | Meaning |
|------|---------|
| `-n name` | Table/map name (default: `geoip`) |
| `-p ports` | Comma-separated ports/ranges (e.g. `80,443` or `1000-2000`) |
| `-w` | Whitelist mode (default: blacklist) |
| `CC` | Two-letter country codes (e.g. `DE ES FR`) |

## Examples

```bash
# Block Germany + Russia on all ports
sudo ./nft-geoblock.sh DE RU

# Block Switzerland only on 80/443
sudo ./nft-geoblock.sh -p 80,443 CH

# Allow only France on 100-200, drop everyone else
sudo ./nft-geoblock.sh -w -p 100-200 FR
```

## Notes

- Requires `root`, `nft`, and `curl`.
- **Port 22 (SSH) is never filtered.** Without `-p` it is auto-exempted; with `-p` any occurrence of `22` (incl. inside ranges) aborts the script.
- Rules hook `input` at `priority mangle`, policy `accept`.
- IP lists are fetched from `ipdeny.com`.
