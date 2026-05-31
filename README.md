# domainset

Generate `ads.txt` from [OISD big](https://big.oisd.nl).

The generator has one input and one output:

```text
https://big.oisd.nl -> ads.txt
```

`ads.txt` contains one domain-set entry per line. OISD rules like this:

```text
||example.com^
```

become:

```text
.example.com
```

Blank lines, comments beginning with `!`, and the `[Adblock Plus]` header are
allowed. Any other input shape is an error.

## Run

```sh
bash ./domainset-generator.sh
```

The script writes `ads.txt` in the repository root.

The output must contain at least 300000 domains. Anything smaller is treated as
an upstream or parser failure.

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

GitHub Actions runs the same checks, then publishes `ads.txt` to the `latest`
release on schedule or manual dispatch.
