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

上游的 `server=/example.cn/114.114.114.114` 转换为 `.example.cn`；
DNS 地址只用于识别输入结构，不会写入输出。顶级规则 `/cn/` 转换为 `.cn`。
OISD 的 `||example.com^` 转换为 `.example.com`。
前导点在 Surge 中匹配域名本身及全部子域名。其他客户端需使用其支持的格式。

## 运行

```sh
bash ./domainset-generator.sh
```

输出到**当前工作目录**的 `ads.txt`、`china.txt`，按字典序排序并去重。
依赖 Bash、curl、awk、sort、mktemp、wc。发布元数据另外需要 jq 和 SHA256 工具。

下载、解析失败或任一列表少于 50,000 条时，自动任务不发布。
解析器允许对应格式的注释和空行，遇到其他输入立即报错，避免静默丢弃规则。

## 异常变化检测

自动任务下载 `latest` 发布中的两份列表，分别与新结果比较。
任一列表条数增加或减少**超过 30%**时中止发布，保留现有 Release。
初次发布没有基线时，只检查最低条数；读取已有发布失败时不会跳过比较。
这是条数检测，不保证能够发现数量相近的内容替换或所有上游错误。

本地可指定基线目录：

```sh
PREVIOUS_DIR=/path/to/previous bash ./domainset-generator.sh
```

确认大幅变化确属上游正常调整后，可在 Actions 手动运行时勾选
`allow_large_change`。此选项仅跳过相对变化限制，下载、格式和最低条数校验仍生效。

## 发布与校验

GitHub Actions 每日定时或手动生成，两份列表都通过校验后才进入发布步骤。
`latest` 是固定标签，附件持续覆盖，不保存历史快照；多个附件的上传不是原子操作。
发布页显示生成时间、条数和来源，另附：

- `SHA256SUMS`：两份列表的 SHA256 校验和。
- `manifest.json`：UTC 生成时间、生成器提交、格式、来源、条数和校验和。

同时下载列表和校验和后执行 `sha256sum -c SHA256SUMS`；macOS 可用
`shasum -a 256 -c SHA256SUMS`。覆盖更新期间如校验不一致，请重新下载整组文件。

## 检查

```sh
shellcheck ./domainset-generator.sh ./tests/*.bash ./scripts/*.bash
bash ./tests/normalize.bash
bash ./tests/reliability.bash
```
