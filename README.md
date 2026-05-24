# domainset

Generate normalized domain-set files from public blocklist sources.

## Outputs

| File | Source | Format |
| --- | --- | --- |
| `ads.txt` | OISD big | one domain per line |
| `nsfw.txt` | OISD NSFW | one domain per line |
| `chinese-mainland.txt` | felixonmars dnsmasq china list | one domain per line |

Generated entries are sorted with `LC_ALL=C sort -u`.

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

`MIN_LINES` sets the default minimum number of generated lines required for each
output file. Individual outputs can override it:

```sh
ADS_MIN_LINES=100000
NSFW_MIN_LINES=1000
CHINESE_MAINLAND_MIN_LINES=10000
```

The GitHub Actions workflow exposes the same thresholds as manual dispatch
inputs.

## Tests

Run the normalization tests with:

```sh
bash tests/normalize.bash
```
