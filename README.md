# domainset

Converts three fixed upstream lists into **Surge DOMAIN-SET** text files, one domain suffix rule per line, updated daily.

| File | Upstream | Purpose |
| --- | --- | --- |
| [ads.txt](https://github.com/oooqqqa/domainset/releases/download/latest/ads.txt) | [OISD big](https://big.oisd.nl) | Domain-level blocking |
| [china.txt](https://github.com/oooqqqa/domainset/releases/download/latest/china.txt) | [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list/blob/master/accelerated-domains.china.conf) | DNS routing: resolve with a DNS resolver suited to networks in China |
| [apple-china.txt](https://github.com/oooqqqa/domainset/releases/download/latest/apple-china.txt) | [dnsmasq-china-list Apple China](https://github.com/felixonmars/dnsmasq-china-list/blob/master/apple.china.conf) | China DNS routing for Apple services |

## What china.txt and apple-china.txt mean

The `china.txt` upstream selects domains that resolve faster or get better CDN results through a Chinese DNS resolver; it may include overseas sites.
`apple-china.txt` contains only the upstream Apple China accelerated domains and does not overlap with `china.txt`.
Neither list indicates the nationality of a site or company, nor guarantees that every matching connection is suitable for `DIRECT`.
Configure DNS resolver selection and outbound connection policy separately, and verify the results on your actual network.
This project provides domain lists only; it does not include DNS server addresses or outbound policies.

## Conversion rules

| Upstream line | Output |
| --- | --- |
| `\|\|example.com^` (OISD) | `.example.com` |
| `server=/example.cn/114.114.114.114` (dnsmasq) | `.example.cn` |
| `server=/cn/114.114.114.114` (top-level rule) | `.cn` |

- Domains are lowercased, sorted and deduplicated. DNS addresses in dnsmasq rules are not written to the output.
- Blank lines, the OISD `[Adblock Plus]` header and `!` comments, and dnsmasq `#` comments are skipped.
- Any other input or invalid domain fails immediately with its line number; rules are never silently dropped.

In Surge, a leading dot matches the domain itself and all of its subdomains.

## Publishing safeguards

- The three lists are replaced together only after all of them pass validation; if any fails, the existing files and Release stay unchanged.
- Each list has a minimum entry count (about 70% of the upstream size) to guard against an empty, sharply shrunken or truncated upstream download.
  Raise it manually as the upstream grows.

The `latest` Release must exist beforehand. Its assets are overwritten on each run and no history is kept; it also carries `manifest.json`
(generation time, generator commit, sources, entry counts and SHA256 checksums).

## Running locally and development

```sh
bash ./domainset-generator.sh   # writes to the current directory
```

Requires Bash 3.2+ and curl 7.71+.

Tests simulate the upstreams by replacing `fetch_url`, so they do not access the network. They require jq:

```sh
shellcheck ./domainset-generator.sh ./tests/*.bash ./scripts/*.bash
bash ./tests/normalize.bash
bash ./tests/reliability.bash
```
