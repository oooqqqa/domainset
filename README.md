# domainset

将三个固定上游转换为 **Surge DOMAIN-SET** 文本，每行一个域名后缀规则，每日自动更新。

| 文件 | 上游 | 用途 |
| --- | --- | --- |
| [ads.txt](https://github.com/oooqqqa/domainset/releases/download/latest/ads.txt) | [OISD big](https://big.oisd.nl) | 域名级拦截 |
| [china.txt](https://github.com/oooqqqa/domainset/releases/download/latest/china.txt) | [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list/blob/master/accelerated-domains.china.conf) | DNS 分流：交给适合中国网络的 DNS 解析器 |
| [apple-china.txt](https://github.com/oooqqqa/domainset/releases/download/latest/apple-china.txt) | [dnsmasq-china-list Apple China](https://github.com/felixonmars/dnsmasq-china-list/blob/master/apple.china.conf) | Apple 服务的中国 DNS 分流 |

## china.txt 和 apple-china.txt 的含义

`china.txt` 上游选择的是使用中国 DNS 解析更快或 CDN 结果更合适的域名，可能包含海外网站。
`apple-china.txt` 单独收录上游 Apple 中国加速域名，与 `china.txt` 不重叠。
这两份列表不代表网站或公司的国籍，也不保证所有匹配的连接都适合 `DIRECT`。
请将 DNS 解析服务器选择与连接出站策略分别配置，并按实际网络验证效果。
本项目只提供域名列表，不包含 DNS 服务器地址或出站策略。

## 转换规则

| 上游行 | 输出 |
| --- | --- |
| `\|\|example.com^`（OISD） | `.example.com` |
| `server=/example.cn/114.114.114.114`（dnsmasq） | `.example.cn` |
| `server=/cn/114.114.114.114`（顶级规则） | `.cn` |

- 域名统一转为小写，排序去重。dnsmasq 规则中的 DNS 地址不写入输出。
- 跳过空行、OISD 的 `[Adblock Plus]` 头和 `!` 注释、dnsmasq 的 `#` 注释。
- 其他任何输入或不合法的域名都立即报错并给出行号，不静默丢弃规则。

前导点在 Surge 中匹配域名本身及全部子域名。

## 发布保护

- 三份列表都通过校验后才一起替换；任一失败时原有文件和 Release 保持不变。
- 每份列表有最低条数（约为上游规模的七成），防止上游变空、大幅缩水或下载被截断。
  上游正常增长后需手动调高。

Release `latest` 的附件持续覆盖，不保存历史；附带 `SHA256SUMS` 和 `manifest.json`
（生成时间、生成器提交、来源、条数和校验和）。

## 本地运行与开发

```sh
bash ./domainset-generator.sh   # 输出到当前目录
```

依赖 Bash 3.2+、curl 7.71+。

测试用替换 `fetch_url` 的方式模拟上游，不访问网络，需要 jq：

```sh
shellcheck ./domainset-generator.sh ./tests/*.bash ./scripts/*.bash
bash ./tests/normalize.bash
bash ./tests/reliability.bash
```
