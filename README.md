# domainset

Generate normalized domain-set files from public blocklist sources.

## Download

Latest generated files are published on the `latest` GitHub Release.

Release assets include the generated lists, `SHA256SUMS`, and `manifest.json`.

## Outputs

| File | Source | Format |
| --- | --- | --- |
| `ads.txt` | OISD big | one domain per line |
| `nsfw.txt` | OISD NSFW | one domain per line |
| `chinese-mainland.txt` | felixonmars dnsmasq china list | one domain per line |

Generated entries are sorted with `LC_ALL=C sort -u`.

The GitHub release also includes:

| File | Contents |
| --- | --- |
| `SHA256SUMS` | SHA-256 checksums for generated lists |
| `manifest.json` | generation time, commit, source URLs, line counts, and checksums |

## Accepted Input Formats

The generator accepts these upstream formats:

```text
||example.com^
example.com
.example.com
server=/example.com/114.114.114.114
```

They normalize to:

```text
.example.com
example.com
.example.com
.example.com
```

Blank lines and comment lines beginning with `#`, `!`, or `;` are ignored.
Unsupported or invalid lines are skipped with a warning that includes the source
name and up to five skipped samples.

## Validation

Domains are lowercased and must contain at least two labels. Each label must be
1 to 63 characters, start and end with an ASCII letter or digit, and contain
only ASCII letters, digits, or hyphens.

## Line Count Guards

Each output has a default minimum number of generated lines required before it
can be published:

| File | Default minimum |
| --- | ---: |
| `ads.txt` | 300000 |
| `nsfw.txt` | 300000 |
| `chinese-mainland.txt` | 100000 |

`MIN_LINES` can override the default minimum for all output files. Individual
outputs can override it:

```sh
MIN_LINES=1000
ADS_MIN_LINES=100000
NSFW_MIN_LINES=1000
CHINESE_MAINLAND_MIN_LINES=10000
```

The GitHub Actions workflow exposes the same thresholds as manual dispatch
inputs. Thresholds must be non-negative integers.

## Tests

Release asset generation uses `jq` to write `manifest.json`.

Run the normalization tests with:

```sh
bash tests/normalize.bash
bash tests/release-assets.bash
```
