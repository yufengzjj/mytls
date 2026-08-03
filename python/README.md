# Python 侧：让 httpx 的 HTTP/2 层也像 Chrome

这个 OpenSSL fork 负责 **TLS 层**的指纹。但一旦协商到 h2，服务端还能看到两层与
OpenSSL 无关、完全由 Python 决定的指纹：

* **HTTP/2 帧层**（akamai 指纹）—— SETTINGS 的项/顺序/数值、连接级 WINDOW_UPDATE、
  PRIORITY、伪头顺序。由 httpcore 和 h2 决定。
* **HPACK 字节层** —— 同样的头，用不同的 huffman/索引策略编出来的字节流不同。
  由 hpack 决定。

不管这两层，就会出现"TLS 装得很像 Chrome，但 h2 一开口就露馅"。本目录负责补齐。

对齐目标：**Chrome 150 桌面版（Windows）**。

这里面的改动**并非同等重要** —— 有的能用公开指纹哈希验证，有的纯属顺手。
动手改之前请先看下面的[三档可信度](#三档可信度)。

---

## 文件

| 文件 | 作用 |
|---|---|
| `chrome_h2.py` | 主角。`import` 即给 httpcore/h2/hpack 打补丁；`describe()` / `TARGET` 报告当前对标的版本 |
| `verify_fp.py` | 拿 `references/chrome150_peet.json` 当基准逐字段校验 |
| `hpack_probe.py` | 起一个 h2 服务器，抓客户端的**原始 ClientHello 和 HPACK 字节**，用于和真 Chrome 逐字节 diff |
| `references/chrome150_peet.json` | 真 Chrome 150 在 tls.peet.ws 上的完整指纹 |
| `references/chrome150_probe.json` | 真 Chrome 150 的**原始 ClientHello + HEADERS 帧**（`hpack_probe.py` 抓的） |

---

## 用法

```python
import chrome_h2          # 打补丁，必须在建 client 之前
import httpx

r = httpx.Client(http2=True).get("https://example.com/")
```

不用传任何参数，也不用改现有代码 —— `requests` / `aiohttp` 之外凡是走
`httpx` + `httpcore` 的都自动生效（补丁打在 httpcore 的模块属性上）。

想知道当前对标的是什么：

```python
>>> print(chrome_h2.describe())
chrome_h2 target
  chrome        : 150.0.0.0
  user-agent    : Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/150.0.0.0 Safari/537.36
  sec-ch-ua     : "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"
  platform      : "Windows"
  accept-language: en-US,en;q=0.9
  cache-control : not sent
  profile       : navigate (capture was sec-fetch-mode: navigate)
  akamai        : 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  derived from  : .../references/chrome150_probe.json
  patched       : yes
```

同样的内容也在 `chrome_h2.TARGET` 这个 dict 里，可以直接取字段。

几个可调项：

```python
chrome_h2.PROFILE = "navigate"      # 或 "xhr"
chrome_h2.ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9"
chrome_h2.SEND_CACHE_CONTROL = True # 见下方"两个会变的头"

chrome_h2.disable()                 # 还原成 httpcore 原样
chrome_h2.enable()
```

**没有 `CHROME_VERSION` 这个开关。** 版本、UA、`sec-ch-ua`、`accept`、`sec-fetch-*`、
header 顺序全部从 `REFERENCE_CAPTURE` 指向的抓包**派生**，不是手写常量 —— 见下面的
[换 Chrome 版本](#换-chrome-版本)。

---

## 前置条件

**必须**用链接了本仓库这个 OpenSSL 的 Python，否则只有 h2 层像 Chrome，TLS 层还是
系统 OpenSSL 的样子。

```bash
# 1. 编译安装本仓库（注意仓库是 CRLF，Linux/WSL 下要先转换）
find . -path ./.git -prune -o -type f -print0 | xargs -0 sed -i 's/\r$//'
./Configure linux-x86_64 shared enable-brotli \
    --prefix=$HOME/openssl --libdir=lib --openssldir=/etc/ssl
make -j4 && make install_sw

# 2. 用它编 Python
export MYTLS=$HOME/openssl
CONFIGURE_OPTS="--with-openssl=$MYTLS --with-openssl-rpath=auto" \
CPPFLAGS="-I$MYTLS/include" \
LDFLAGS="-L$MYTLS/lib -Wl,-rpath,$MYTLS/lib" \
MAKE_OPTS="-j4" \
pyenv install 3.11.15

# 3. 依赖
pip install "httpx[http2]==0.27.2" brotli zstandard
```

* `enable-brotli` 是必须的 —— ClientHello 里无条件宣告 brotli 证书压缩，没有它遇到
  会压缩证书链的服务器（Cloudflare 部分配置）握手会失败。
* `--openssldir=/etc/ssl` 让 `ssl.create_default_context()` 能直接找到根证书，
  否则每处都要传 `cafile=`。
* **httpx 锁 0.27.2**。本模块直接改 httpcore 内部，版本不符会 `warnings.warn`。

验证装对了：

```python
import ssl; print(ssl.OPENSSL_VERSION)   # 应为 OpenSSL 3.4.0
```

---

## 具体做了什么

### 1. SETTINGS / WINDOW_UPDATE

```
Chrome  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p   md5 52d84b11737d980aef856699f885ca86
httpx   1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p
```

数值取自 Chromium `net/http/http_network_session.cc` 的 `AddDefaultHttp2Settings()`
和 `net/spdy/spdy_session.cc` 的 `SendInitialData()`。`spdy::SettingsMap` 是
`std::map`，所以按 ID 升序发 1,2,4,6 —— **没有** MAX_CONCURRENT_STREAMS(3) 和
MAX_FRAME_SIZE(5)。WINDOW_UPDATE = 15M − 65535 = 15663105。

伪头顺序 `m,a,s,p` httpcore 本来就一致，没动。

### 2. HEADERS 帧的优先级

Chrome 不发独立 PRIORITY 帧（所以 akamai 第三段是 `0`），但会在 HEADERS 上带
RFC 7540 优先级：exclusive=1, depends_on=0, weight=256。

同时**去掉**了 httpcore 在 HEADERS 之后发的 per-stream WINDOW_UPDATE —— 我们已经在
SETTINGS 里宣告 6MB 流窗口，Chrome 不发这一帧。

### 3. 请求头

两套模板，`navigate`（默认）和 `xhr`，顺序取自真实抓包。

合并规则 —— **模板决定"哪些头、什么顺序"，调用方决定"值"以及追加哪些额外头**：

| 调用方传的 | 结果 |
|---|---|
| 模板里已有的名字 | 值被覆盖，**位置保持模板的位置** |
| 模板里没有的名字 | 从 `accept` 之后的 `_EXTRA` 槽位插入，保持调用方给的相对顺序 |
| `host` / `connection` / `keep-alive` / `transfer-encoding` / `upgrade` | 一律丢弃（`host` 变成 `:authority`，其余是 HTTP/1 专用） |

httpx 自己注入的四个默认头（`accept: */*`、`accept-encoding`、`connection: keep-alive`、
`user-agent: python-httpx/x.y.z`）会先被剔除，否则会被误当成调用方的意图。

两个已知的行为怪癖：

* 剔除靠的是 **(名字, 值) 精确匹配**，所以调用方如果**真的**想发
  `user-agent: python-httpx/0.27.2`，会被误判成 httpx 的默认值而丢掉。除这四个值以外
  不受影响。
* **没法删掉模板里的头。** 传空值只会让它变成空串。要去掉只能改 `_template()`，
  或者换 `PROFILE = "xhr"`（xhr 模板本来就没有 `upgrade-insecure-requests` /
  `sec-fetch-user` / `cache-control`）。

### 4. HPACK 编码策略

对齐 quiche（`quiche/http2/hpack/hpack_encoder.cc`）：

| | Chrome (quiche) | hpack 原样 |
|---|---|---|
| Huffman | 算完长度，**严格更短**才用 | 无条件用 |
| never-indexed | 从不发这个 opcode | `authorization` / 短 `cookie` 强制 never-indexed |
| 动态表 | 伪头除 `:authority` 外都不索引 | 全部索引 |
| cookie | 按 `;` 拆成多个字段 | 不拆 |

第三条影响最大：`:path` 被塞进动态表会让整条连接后续所有请求的表状态和 Chrome 分叉。

h2 的 never-indexed 规则源码注释里写明是"照 Firefox 和 nghttp2"，本来就不是 Chrome。

---

## 三档可信度

本目录的改动分三档，**收益依据的强度差别很大**，别当成同等重要。

### 第一档：进指纹哈希的 —— 有实证

只有两样：

* **TLS 层**（JA3 / JA4 / peetprint）—— 由 C 库负责，本目录不涉及
* **akamai 指纹** —— SETTINGS、连接级 WINDOW_UPDATE、PRIORITY、**伪头**顺序，
  就这四段

这两样能对着 `references/` 里的真 Chrome 抓包逐字段比对，对上就是对上了。

### 第二档：header 的集合 —— 逻辑上站得住，但不进任何哈希

**普通 header（名字、值、顺序）不在上面任何一个哈希里。** 可以自己验证：

```python
# 把 header 砍到只剩 3 个、顺序打乱、UA 改成 totally-not-chrome/1.0
# → ja4 和 akamai_fingerprint_hash 一个字符都不变
```

实测确认过。所以 header 模板对"指纹哈希"的贡献是**零**。

它的价值在别处：一个请求 UA 写着 `Chrome/150`，却没有 `sec-ch-ua`、没有 `sec-fetch-*`、
没有 `accept-language`，这本身是自相矛盾的，一条规则就能判掉，不需要什么指纹库。
模板真正的作用是——**你什么都不传就得到一套自洽的 Chrome 头**。这一档我认为价值是实的。

### 第三档：header 顺序 与 HPACK 字节 —— 做到了，但收益无实证

* **header 顺序**：反爬会校验 header order 这个说法在业内材料里很常见，但
  **本项目没有验证过任何一家真的在查**。既然已经在构造这个列表，顺手排对不额外花钱。
* **HPACK 字节**：那四处编码策略对齐（条件 huffman、不发 never-indexed、伪头不进动态表、
  cookie 拆分）确实做到了和真 Chrome **逐字节相同**（455 字节，见下方验证），这是事实。
  但**有没有人真的去哈希 HEADERS 的原始字节，没有任何证据**，实际收益可能接近于零。

留着的理由是成本而非收益：代码已写好、运行时开销为零、已验证不破坏功能。
如果觉得维护负担不值（尤其 `sec-ch-ua` 跨大版本要重新抓包这一条），
删掉 `_build_headers` 和 `_ChromeHpackEncoder`、只保留 SETTINGS/WINDOW_UPDATE/priority，
akamai 和 TLS 照样全对。

---

## 验证

三层都有真实 Chrome 参照，全部验证通过。**注意这里的"通过"只对第一档构成指纹证据**，
第二、三档是"与真 Chrome 一致"，不等于"有人在查"。

### TLS + h2 帧 + 头

```bash
python verify_fp.py            # TLS(无 PSK) + 完整 h2 层
python verify_fp.py --resume   # TLS 含 PSK，对应参考文件的场景
```

`--resume` 那次应当八项全 OK，包括
`ja4 = t13d1517h2_8daaf6152771_a87ad97598a9` 和
`peetprint_hash = 35fc5e864929e3b01e9ba9eb41bc1360`。

不带 `--resume` 时 `ja4` 会少一个扩展（`0029` pre_shared_key）、`peetprint_hash`
随之不同 —— **这是对的**，Chrome 首次连接同样如此。

### 原始字节（ClientHello + HPACK）

peet.ws 给的是它**解读后**的结果，拿不到线上的确切字节 —— 比如两个 GREASE 扩展它都显示
成空对象 `{}`，看不出第二个其实带一个 `00`。这类问题只有原始字节能回答。

`hpack_probe.py` 起一个最小 h2 服务器，两层一起抓：

* **ClientHello** —— 明文发送、在任何密钥交换之前，所以用 `MSG_PEEK` 先偷看再交给
  TLS 层即可，**不需要抓包、不需要 SSLKEYLOGFILE**。
* **HPACK header block** —— 在任何解码发生之前原样落盘。

```bash
# 终端 1：等 Chrome
python hpack_probe.py serve --out chrome.json
```

```
:: Windows 上用现成的 Chrome，全新 profile 避免 cookie/扩展污染
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
  --user-data-dir=%TEMP%\cfp --ignore-certificate-errors ^
  https://localhost:8443/api/all
```

Chrome 会挂一条 `You are using an unsupported command-line flag` 黄条 —— 那说明
flag **生效了**，不是错误。

```bash
# 终端 2：抓我们自己的，然后比
python hpack_probe.py serve --out ours.json &
python hpack_probe.py client
python hpack_probe.py diff references/chrome150_probe.json ours.json
```

`diff` 会先比 ClientHello（record/legacy 版本、session_id 长度、cipher 列表、
每个扩展的类型与 body 长度；GREASE 的**值**通配掉，因为它本来就该每连接都变，但
**长度**不通配），再比 HPACK 字节。

只比第一个 HEADERS 帧：HPACK 动态表有状态，只有连接刚建立时两边都是空表才可比。

**比之前必须把变量对齐**，否则头都不一样、比字节没有意义：

```python
chrome_h2.SEND_CACHE_CONTROL = False        # 全新导航不发
chrome_h2.ACCEPT_LANGUAGE = "en-US,en;q=0.9" # 全新 profile 是 en-US
```

再加上两边用同一个端口（`:authority` 要一致）。当前结果：ClientHello 七项全 OK，HPACK **455 字节完全相同**。

扩展**顺序**不参与比较 —— Chrome 和我们都是每连接随机打乱的，只有集合、每项的 body 长度、以及首尾两个位置（GREASE 固定在最前、倒数第二）才是形状的一部分。

自签证书和临时文件落在 `~/.cache/hpack_probe/`，不进仓库；
`HPACK_PROBE_DIR` 可改。

---

## 换 Chrome 版本

抓一次新的就行，不用改代码：

```bash
python hpack_probe.py serve --out references/chrome151_probe.json
# Chrome 访问 https://localhost:8443/api/all 一次
```

然后把 `chrome_h2.py` 里的 `REFERENCE_CAPTURE` 指到新文件。`TARGET`、UA、
`sec-ch-ua`、`accept`、header 顺序、`accept-language` 默认值、要不要发
`cache-control`，全部自动跟着变。

**这样设计是因为手写常量会烂。** `sec-ch-ua` 的品牌排列 Chromium 每个大版本都重排 ——
Chrome 150 是 `"Not;A=Brand";v="8"` 打头，早期版本是末尾的 `"Not_A Brand";v="99"`。
以前光改一个 `CHROME_VERSION` 只会得到一个**看着像、实际不对**的值。现在这种错误做不出来了。

换完之后跑一遍验证确认新旧差异：

```bash
python hpack_probe.py diff references/chrome150_probe.json references/chrome151_probe.json
```

---

## 两个会变的头

抓包时发现这两项 Chrome 自己就不固定，别当成常量：

* **`cache-control: max-age=0`** —— 刷新或地址栏回车重进时发，**全新地址导航不发**。
  两种情况都在真实抓包里见过。开关是 `SEND_CACHE_CONTROL`。
* **`accept-language`** —— 跟 Chrome 的界面语言走。默认 `zh-CN,zh;q=0.9`（对应参考
  文件），全新 profile 是 `en-US,en;q=0.9`。

---

## 已知不做 / 注意

* **`xhr` 模板仍是手写的。** 只有 `navigate` 是从抓包派生的 —— 我没有 XHR 的一手抓包。
  它用的 UA / `sec-ch-ua` / `accept-language` 会跟着抓包走，但头的集合与顺序是推断的。
* **SETTINGS GREASE 不模拟。** Chrome 能发第五个 GREASE 设置，但 id 和值都是每连接随机，
  且 `enable_http2_settings_grease` 默认关。网上流传的固定值本身就是特征。
* **`xhr` 模板的顺序未经一手抓包确认**，头的集合是确定的，顺序是推断的。
* **这是 monkeypatch。** httpx/httpcore/h2 版本一变就可能失配，`import` 时会校验并告警。
  升级前请重跑上面全部验证。
* **只覆盖 h2。** `httpx.Client()`（http/1.1）没有 SETTINGS 那种指纹面，只剩头顺序，
  但本模块的头模板只作用于 h2 路径。
