# domainset

将两个固定上游转换为 **Surge DOMAIN-SET** 文本，每行一个域名后缀规则。

| 文件 | 上游 | 用途 |
| --- | --- | --- |
| [ads.txt](https://github.com/oooqqqa/domainset/releases/download/latest/ads.txt) | [OISD big](https://big.oisd.nl) | 域名级拦截 |
| [china.txt](https://github.com/oooqqqa/domainset/releases/download/latest/china.txt) | [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list/blob/master/accelerated-domains.china.conf) | DNS 分流：交给适合中国网络的 DNS 解析器 |

## china.txt 的含义

上游选择的是使用中国 DNS 解析更快或 CDN 结果更合适的域名，可能包含海外网站。
此列表不代表网站或公司的国籍，也不保证所有匹配的连接都适合 `DIRECT`。
请将 DNS 解析服务器选择与连接出站策略分别配置，并按实际网络验证效果。
本项目只提供域名列表，不包含 DNS 服务器地址或出站策略。

## 转换规则

| 上游行 | 输出 |
| --- | --- |
| `\|\|example.com^`（OISD） | `.example.com` |
| `server=/example.cn/114.114.114.114`（dnsmasq） | `.example.cn` |
| `server=/cn/114.114.114.114`（顶级规则） | `.cn` |

- 域名统一转为小写。dnsmasq 规则中的 DNS 地址只用于识别格式，不写入输出。
- 域名总长不超过 253；每段 1–63 个字符，只含字母、数字和 `-`，且首尾不能是 `-`。
  OISD 至少两段，dnsmasq 允许单段（如 `cn`）。
- 跳过空行、OISD 的 `[Adblock Plus]` 头和 `!` 注释、dnsmasq 的 `#` 注释。
- 其他任何输入都立即报错并给出行号，避免静默丢弃规则。

前导点在 Surge 中匹配域名本身及全部子域名。其他客户端需使用其支持的格式。

## 运行

```sh
bash ./domainset-generator.sh
```

输出到**当前工作目录**的 `ads.txt`、`china.txt`，按字典序排序并去重，文件权限遵循 umask。
成功时打印每份列表的条数；任一步骤失败时以非零状态退出，原有文件保持不变。

| 环境变量 | 默认值 | 作用 |
| --- | --- | --- |
| `PREVIOUS_DIR` | 空 | 基线目录，需包含非空的 `ads.txt` 和 `china.txt`；设置后启用变化检测 |
| `ALLOW_LARGE_CHANGE` | `false` | 设为 `true` 时允许超过 30% 的条数变化 |

依赖 Bash（macOS 自带的 3.2 可用）、curl 7.71 及以上、awk、sort、mktemp、wc。

## 处理流程

1. 在输出目录下创建临时目录 `.domainset.XXXXXX`，退出时自动删除。
2. 依次处理 `ads.txt` 和 `china.txt`：
   1. curl 下载到临时文件：连接超时 10 秒，单次最长 120 秒；失败时重试 2 次，间隔 10 秒。
   2. 按转换规则解析，排序去重。
   3. 检查最低条数：每份列表至少 50,000 条。
   4. 设置了 `PREVIOUS_DIR` 时，与基线比较条数变化。
3. 两份列表都通过后，才依次移动到输出路径。

只有下载会重试；格式、条数和变化校验的结果是确定的，失败时直接退出。

## 异常变化检测

任一列表条数相比基线增加或减少**超过 30%**时中止，保留原有文件和现有 Release。
这是条数检测，不保证能够发现数量相近的内容替换或所有上游错误。

本地可指定基线目录：

```sh
PREVIOUS_DIR=/path/to/previous bash ./domainset-generator.sh
```

自动任务使用 `latest` 发布中的两份列表作为基线。初次发布没有基线时只检查最低条数；
查询或下载已有发布失败时任务失败，不会当作初次发布而跳过比较。

确认大幅变化确属上游正常调整后，可在 Actions 手动运行时勾选
`allow_large_change`。此选项仅跳过相对变化限制，下载、格式和最低条数校验仍生效。

## 发布与校验

工作流 `.github/workflows/generate-lists.yml`：

- 推送到 `main` 或 pull request：只运行[检查](#开发)。
- 每日 06:11 UTC 定时运行或手动运行：检查通过后生成并发布。

发布步骤：

1. 查询 `latest` 发布是否存在；存在时下载两份列表作为基线。
2. 运行生成器，失败时不进入后续步骤。
3. 生成 `SHA256SUMS`、`manifest.json` 和发布说明。
4. 覆盖上传四个附件，把 `latest` 标签移到当前提交，更新发布说明，删除其他附件。
   初次发布时创建标签和 Release。

`latest` 是固定标签名，附件持续覆盖，不保存历史快照；该 Release 不标记为 GitHub 的 Latest release。
发布页显示生成时间、条数和来源，另附：

- `SHA256SUMS`：两份列表的 SHA256 校验和。
- `manifest.json`：UTC 生成时间、生成器提交、格式、来源、条数和校验和。

多个附件逐个上传，不是原子操作。同时下载列表和校验和后执行 `sha256sum -c SHA256SUMS`；
macOS 可用 `shasum -a 256 -c SHA256SUMS`。覆盖更新期间如校验不一致，请重新下载整组文件。

## 开发

| 文件 | 内容 |
| --- | --- |
| `domainset-generator.sh` | 下载、解析、校验并替换输出；被 `source` 时只加载函数和配置 |
| `scripts/release-metadata.bash` | 生成发布元数据；需要 jq 和环境变量 `GITHUB_SHA` |
| `tests/normalize.bash` | 转换规则和完整生成流程 |
| `tests/reliability.bash` | 失败处理、变化阈值和发布元数据 |

测试通过替换 `fetch_url` 模拟上游，不访问网络，需要 jq。CI 每次运行都会执行：

```sh
shellcheck ./domainset-generator.sh ./tests/*.bash ./scripts/*.bash
bash ./tests/normalize.bash
bash ./tests/reliability.bash
```
