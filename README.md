# domainset

Generate domain-set text files from upstream domain lists.

The generator has two inputs and two outputs:

```text
https://big.oisd.nl -> ads.txt
https://github.com/felixonmars/dnsmasq-china-list/blob/master/accelerated-domains.china.conf -> china.txt
```

Each output contains one domain-set entry per line. OISD rules like this:

```text
||example.com^
```

become:

```text
.example.com
```

Blank lines, comments beginning with `!`, and the `[Adblock Plus]` header are
allowed. Any other input shape is an error.

dnsmasq-china-list rules like this:

```text
server=/example.cn/114.114.114.114
```

become:

```text
.example.cn
```

Top-level rules such as `server=/cn/114.114.114.114` become `.cn`.

Blank lines and comments beginning with `#` are allowed. Any other input shape
is an error.

## Run

```sh
bash ./domainset-generator.sh
```

The script writes `ads.txt` and `china.txt` in the repository root.

`ads.txt` must contain at least 50000 domains, and `china.txt` must contain at
least 100000 domains. Anything smaller is treated as an upstream or parser
failure.

## Requirements

- bash
- curl
- awk
- sort

## Checks

```sh
shellcheck ./domainset-generator.sh ./tests/normalize.bash
bash ./tests/normalize.bash
```

GitHub Actions runs the same checks, then publishes both files to the `latest`
release on schedule or manual dispatch.
