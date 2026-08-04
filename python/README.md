# Python 侧：让 httpx 的 HTTP/2 层也像真实浏览器

这个 OpenSSL fork 负责 **TLS 层**的指纹。但一旦协商到 h2，服务端还能看到两层与
OpenSSL 无关、完全由 Python 决定的指纹：

* **HTTP/2 帧层**（akamai 指纹）—— SETTINGS 的项/顺序/数值、连接级 WINDOW_UPDATE、
  PRIORITY、伪头顺序。由 httpcore 和 h2 决定。
* **HPACK 字节层** —— 同样的头，用不同的 huffman/索引策略编出来的字节流不同。
  由 hpack 决定。

不管这两层，就会出现"TLS 装得很像 Chrome，但 h2 一开口就露馅"。本目录负责补齐。

**这里没有一行代码是为某个浏览器写的。** 起一个拦截地址，用哪个浏览器访问一次，
就按那个浏览器存成一份标准抓包，并自动多一个 transport —— 不用事先说是什么浏览器，
也不用改代码。当前装了什么：

```bash
python hpack_probe.py list
```

这里面的改动**并非同等重要** —— 有的能用公开指纹哈希验证，有的纯属顺手。
动手改之前请先看下面的[三档可信度](#三档可信度)。

---

## 文件

| 文件 | 作用 |
|---|---|
| `browser_fp.py` | 主角。按 brand 提供 transport；`catalog()` / `describe()` 报告装了哪些、各自对标什么 |
| `hpack_probe.py` | 起一个 h2 服务器抓**原始 ClientHello + h2 帧 + HPACK 字节**；`serve` 抓来访的浏览器，`selftest` 抓自己并逐字节比 |
| `verify_fp.py` | 联网版校验：拿 `references/<brand>.json` 当基准逐字段比 |
| `profiles/<brand>.json` | **一个浏览器一个文件**，`browser_fp` 的一切都从这里派生 |
| `references/<brand>.json` | 同一次抓包里，该浏览器在 **tls.peet.ws + check.ja3.zone** 上的指纹（自动生成）。给 `verify_fp.py` 当基准，也给 `browser_fp` 提供 header 顺序 |

**brand 是浏览器（+平台），不是浏览器版本。** 只有 `chrome.json`，没有 `chrome150.json`
—— 重抓就覆盖，版本从抓包的 UA 里读（`Profile.version`）。这样不会有人被钉在旧 profile 上。

---

## 用法

```python
import browser_fp as fp
import httpx

with httpx.Client(transport=fp.transport("chrome")) as client:
    r = client.get("https://example.com/")
```

`fp.ChromeTransport()` 是同一个东西 —— 类名由 brand 合成（`chrome_android` →
`ChromeAndroidTransport`），异步加 `Async` 前缀：`fp.AsyncChromeTransport()`、
`fp.async_transport("chrome")`。

只装了一个 profile 时 brand 可以省略（`fp.Transport()`）。装了多个又没指定，会直接报错
而不是替你猜 —— 猜错就是发错指纹。要定默认值：

```python
fp.DEFAULT_BRAND = "chrome"          # 或环境变量 BROWSER_FP_BRAND=chrome
```

**`import` 本身什么都不改。** 只有拿到这个 transport 的 client 才有浏览器行为，
同一进程里别的 client 照旧 —— 可以直接对照：

```python
httpx.Client(transport=fp.ChromeTransport())  # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
httpx.Client(http2=True)                      # 1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p
```

### 代理

代理参数传给 **transport**，走代理时指纹照样生效：

```python
transport = fp.ChromeTransport(proxy="http://user:pass@127.0.0.1:8080")
with httpx.Client(transport=transport) as client:
    client.get("https://example.com/")
```

`http://`、`https://`、`socks5://` 都支持，同步异步都一样。

已实测：经 CONNECT 代理和经 SOCKS5 代理各打到本地探针一次，
ClientHello + h2 帧 + HPACK **455 字节与直连完全相同**；再经两种代理访问
tls.peet.ws，akamai 与直连一致，而同一进程里不带 transport 的 client 仍是 httpcore 原样。

`socks5h://` **不能用** —— 那是 httpx 0.27.2 自己不认（`Unknown scheme for proxy URL`），
与本模块无关。SOCKS5 需要 `socksio`，`install-python.sh` 已经装
（`httpx[http2,socks]`）。

**一个坑**：`verify`、`limits`、`proxy` 这类参数要给 **transport**，不是 Client ——
httpx 一旦收到 transport，自己那份就不用了：

```python
fp.ChromeTransport(verify=ctx, proxy=P)          # 对
httpx.Client(transport=..., verify=ctx, proxy=P) # 静默失效
```

### 看当前对标的是什么

```python
>>> print(fp.catalog())
1 profile(s) in .../python/profiles:
  chrome  Chrome 150 on Windows         1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p

>>> print(fp.describe("chrome"))
chrome  (Chrome 150 on Windows)
  transport      : browser_fp.ChromeTransport() / transport('chrome')
  user-agent     : Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/150.0.0.0 Safari/537.36
  sec-ch-ua      : "Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"
  platform       : Windows
  accept-language: en-US,en;q=0.9
  cache-control  : not sent
  header profile : navigate (capture was sec-fetch-mode: navigate)
  hpack          : quiche
  akamai         : 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
  akamai md5     : 52d84b11737d980aef856699f885ca86
  settings       : 1=65536, 2=0, 4=6291456, 6=262144
  window update  : 15663105
  headers prio   : exclusive=True dep=0 weight=256
  derived from   : .../python/profiles/chrome.json
  captured at    : 2026-08-03T10:57:34+00:00
```

命令行同样：`python hpack_probe.py list`、`python browser_fp.py`。

同样的内容在 `fp.profile("chrome").meta` 这个 dict 里，可以直接取字段
（`brand` / `label` / `browser` / `version` / `platform` / `user_agent` / `sec_ch_ua` /
`akamai_fingerprint` / `akamai_hash` / `source` / `captured_at` …）。

### 可调项

三个，都挂在 profile 上，改了对用这个 brand 的所有 transport 生效（包括已建好的连接）：

```python
prof = fp.profile("chrome")
prof.header_profile = "xhr"                  # 或 "navigate"（默认）
prof.accept_language = "zh-CN,zh;q=0.9"
prof.send_cache_control = True               # 见下方"两个会变的头"
```

要"还原成原样"直接别用 transport 就行。

**没有版本常量，也没有写死的 akamai 常量。** 版本、UA、`sec-ch-ua`、`accept`、
`sec-fetch-*`、header 顺序，以及 SETTINGS、WINDOW_UPDATE、HEADERS 优先级、伪头顺序，
全部从 `profiles/<brand>.json` **派生** —— 见下面的[加一个浏览器](#加一个浏览器)。

---

## 前置条件

**必须**用链接了本仓库这个 OpenSSL 的 Python，否则只有 h2 层像浏览器，TLS 层还是
系统 OpenSSL 的样子。整套 `./install-python.sh` 一条命令就能建好；手工的话：

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
pip install "httpx[http2,socks]==0.27.2" brotli zstandard
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

## 加一个浏览器

起服务，用目标浏览器访问一次，完事。**不用事先说是什么浏览器，Python 侧也不用改代码**：

```bash
python hpack_probe.py serve
```

```
:: 让目标浏览器访问一次（Windows 上的 Chrome，全新 profile 避免 cookie/扩展污染）
"C:\Program Files\Google\Chrome\Application\chrome.exe" ^
  --user-data-dir=%TEMP%\cfp --ignore-certificate-errors ^
  https://localhost:8443/api/all
```

Chrome 会挂一条 `You are using an unsupported command-line flag` 黄条 —— 那说明
flag **生效了**，不是错误。手机同理，连同一个网段访问 `https://<你的IP>:8443/api/all`。

```
listening on :8443 - waiting for any h2 client
  captured from 192.168.1.7: Mozilla/5.0 (Linux; Android 14; Pixel 8) ... Chrome/150.0.0.0 Mobile Safari/537.36
  stored as .../profiles/chrome_android.json
  stored as .../references/chrome_android.json  (tls.peet.ws says ja4 t13d1516h2_...)
  ...
chrome_android  (Chrome 150 on Android)
  transport      : browser_fp.ChromeAndroidTransport() / transport('chrome_android')
```

**一次访问出两个文件。** 浏览器请求被抓到之后，我们回给它一个页面，页面里
`fetch('https://tls.peet.ws/api/all')` 再把结果 POST 回来 —— 于是 `profiles/`（原始字节）
和 `references/`（第三方的解读）同时到手，联网校验的基准不用手工去存。

页面同时打两个服务，因为只有一个是所有浏览器都够得着的：

| | CORS | 内容 |
|---|---|---|
| `check.ja3.zone` | **`*`**，任何浏览器任何设备都能拿 | 只有 JA3（hash + 完整串 + ciphers + curves） |
| `tls.peet.ws` | **只有 OPTIONS 预检有，实际 GET 上没有** | ja4 / peetprint / akamai / 完整 header 顺序 |

所以手机等拿不到 flag 的场合，至少 JA3 那份是稳的——而 **JA3 恰恰是 selftest 查不到的**
（ClientHello 永远没法逐字节比，只能比我自己定义的"形状"；第三方独立算的哈希才能证伪它）。

peet 那份默认 Chrome 会被挡掉（`TypeError: Failed to fetch`，实测过），两条路，页面上都写着：

1. 启动浏览器时加 `--disable-web-security`（**必须**同时有 `--user-data-dir`，否则 Chrome
   忽略该 flag）。它只关渲染进程的同源检查，**不碰网络栈**，抓到的指纹不受影响：

   ```
   chrome.exe --user-data-dir=%TEMP%\cfp --ignore-certificate-errors ^
              --disable-web-security https://localhost:8443/api/all
   ```

2. 什么 flag 都不加：页面上**始终**有一个粘贴框，点链接在新标签打开 tls.peet.ws，
   把 JSON 复制粘回去即可；不想弄就点 `skip` 立即结束。

### 两种请求，都要

页面自己那次 fetch 永远是 **XHR**，而手工粘贴的是一次**导航**——浏览器给这两种发的头
不一样，缺一种就有一半模板是推断的。所以：

```bash
python hpack_probe.py serve --both     # 等到两种都齐了才收工
```

一次访问：自动 fetch 给 XHR 那份，粘贴给导航那份。容器**按 kind 累积**——新抓到的种类
覆盖同种类，没抓到的保留旧的，但**只在 UA 完全一致时**（浏览器升级就丢弃，宁可退回推断
也不用过期的顺序）。

reference 长这样，缺哪个就是没拿到：

```json
{"brand": "chrome", "collected_at": "...",
 "peet": [ {...cors 那次...}, {...navigate 那次...} ],
 "ja3zone": {...}}
```

抓包机器不通外网就加 `--no-reference`（或者等它超时，默认 25s，不影响 profile）。
`--out` 那种临时抓包不收 reference。

**brand 是它自己报的**，从刚发过来那个请求的 `user-agent` 读：

| 来访的 | 存成 |
|---|---|
| 桌面 Chrome | `chrome` |
| 安卓 Chrome | `chrome_android` |
| iPhone Safari | `safari_ios` |
| Firefox / Edge / Opera / Vivaldi / 三星 / Yandex | `firefox` / `edge` / `opera` / … |

认不出来（比如 curl）会把抓包留在 `capture.json` 并让你用 `--brand` 指定；
`--brand` 也可以直接覆盖自动判断。抓完立刻打印这个 brand 现在长什么样（`describe()`
的输出），此时：

```python
fp.transport("chrome_android")     # 已经能用
fp.ChromeAndroidTransport()        # 也已经能用
```

想先试用不落地，把 `BROWSER_FP_PROFILES` 指到别的目录即可
（`serve` 也认这个变量，所以抓包会直接落到那儿；reference 那份是 `BROWSER_FP_REFERENCES`）。

**自动派生的部分：**

| | 来源 |
|---|---|
| UA、`sec-ch-ua`、`accept`、`sec-fetch-*`、header 集合与顺序 | HEADERS 帧解出来的 HPACK |
| `accept-language` 默认值、要不要发 `cache-control` | 同上 |
| 浏览器名/版本/平台（`label`、`meta`） | UA 与 `sec-ch-ua-platform` |
| **header 顺序**（含 `referer` / `cookie` 的确切位置） | reference 里那次真实站点请求 |
| **`xhr` 模板的顺序、值、优先级** | reference 里 `sec-fetch-mode: cors` 的那一帧 |
| SETTINGS 的 id / 顺序 / 数值 | SETTINGS 帧 |
| 连接级 WINDOW_UPDATE（0 = 不发） | WINDOW_UPDATE 帧 |
| HEADERS 优先级（没有就不带 PRIORITY 标志） | HEADERS 帧标志位 |
| 伪头顺序（akamai 最后一段） | HPACK 里的 `:` 开头字段 |

**这样设计是因为手写常量会烂。** `sec-ch-ua` 的品牌排列 Chromium 每个大版本都重排 ——
Chrome 150 是 `"Not;A=Brand";v="8"` 打头，早期版本是末尾的 `"Not_A Brand";v="99"`；
akamai 那串数字更是抄错了也看不出来。现在这两类错误都做不出来了。

**唯一猜出来的一项：HPACK 编码策略。** 抓包能告诉你猜错了（字节对不上），但没法告诉你
正确规则是什么，所以按 UA 猜：Chromium 系一律 `quiche`，其余用 hpack 原样（`stock`）。
要覆盖就在抓包 json 里写 `"meta": {"hpack": "quiche"}`。**判断对错的方法就是跑
`selftest`** —— 猜错了 HPACK 那一段就会不同，别的层照样是对的。
目前只实现了 quiche 这一套规则，别的引擎要自己加。

**不自动的部分：TLS 层。** 抓包里的 ClientHello 只用来 diff，没有任何代码消费它 ——
cipher 列表、扩展集合、sigalgs、key_share 个数全部写死在 C 里
（`ssl/ssl_lib.c`、`ssl/statem/extensions_clnt.c`、`ssl/statem/extensions.c`），
改了要重新编译。所以：

* **换 Chrome 版本 / 换成 Android Chrome** —— 同一份 BoringSSL，ClientHello 大概率不用动，
  跑一次 `selftest` 就知道。
* **换成 Safari / iOS / 原生 App** —— TLS 栈完全不同，等于把 C 那部分重做一遍。
  h2 层倒是抓一次就跟着变了（连伪头顺序都是）。

抓完跑一次自检，三层一起比：

```bash
python hpack_probe.py selftest --brand firefox
```

```
=== ClientHello ===          ← 差异要改 C 并重编
=== HTTP/2 frame layer ===   ← 差异说明抓包没被吃进去
=== HPACK header block ===   ← 逐字节
```

---

## 具体做了什么

### 1. SETTINGS / WINDOW_UPDATE

```
Chrome  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p   md5 52d84b11737d980aef856699f885ca86
httpx   1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p
```

这些**不是写死的常量**，是从抓包里的 SETTINGS 帧按原样读出来的（`Profile.settings`
是 `[(id, value)]` 的有序列表，不是 dict —— 顺序本身就是指纹的一部分，不能被排序掉）。
上面的值可以和 Chromium 源码对上：`net/http/http_network_session.cc` 的
`AddDefaultHttp2Settings()` 和 `net/spdy/spdy_session.cc` 的 `SendInitialData()`；
`spdy::SettingsMap` 是 `std::map`，所以按 ID 升序发 1,2,4,6 —— **没有**
MAX_CONCURRENT_STREAMS(3) 和 MAX_FRAME_SIZE(5)。WINDOW_UPDATE = 15M − 65535 = 15663105。

id 3 即使不上线也会塞进 `local_settings`：httpcore 拿它给信号量定容量，而 h2 在这个 key
缺失时返回 2³²+1，httpcore 会去 acquire 四十多亿次，请求永远发不出去。控制上线内容的是
每个 profile 自己那个 `Settings` 子类的 `__iter__`，不是删 key。

伪头顺序也来自抓包（`Profile.pseudo_order`）。Chrome 的 `m,a,s,p` 和 httpcore 本来就
一致，但别的客户端不一定 —— 换 brand 时它会自动跟着变。

### 2. HEADERS 帧的优先级

同样派生自抓包。Chrome 不发独立 PRIORITY 帧（所以 akamai 第三段是 `0`），但会在 HEADERS
上带 RFC 7540 优先级：exclusive=1, depends_on=0, weight=256。抓包里没有优先级时就不带
PRIORITY 标志。

同时**去掉**了 httpcore 在 HEADERS 之后发的 per-stream WINDOW_UPDATE —— 我们已经在
SETTINGS 里宣告 6MB 流窗口，Chrome 不发这一帧。

### 3. 请求头

两套模板，`navigate`（默认）和 `xhr`，顺序都不是手写的：

* **有 reference 时**，顺序直接取自 reference 里那次真实站点请求（navigate 用导航那帧，
  xhr 用 `sec-fetch-mode: cors` 那帧）。**这是唯一能知道 `referer` / `cookie` 放哪的途径**
  —— 打到 localhost 的抓包既没有来源也没有 cookie。实测真 Chrome 把 `referer` 放在
  `sec-fetch-dest` 之后，而不是我原先猜的 `accept` 之后。
* **没有 reference 时**退回从抓包推断：navigate 顺序是真的，xhr 是在它基础上按规则改写
  （`accept` → `*/*`、`sec-fetch-mode` → `cors`、`sec-fetch-dest` → `empty`、
  `priority` → `u=1, i`，去掉 `upgrade-insecure-requests` / `sec-fetch-user`）。

**值永远来自抓包，不来自 reference** —— reference 里那些值描述的是发往别人站点的请求。
`referer` / `cookie` / `origin` / `authorization` 等按请求变化的头只借用位置，
`sec-fetch-site` 用各自 kind 的常见值（`none` / `same-origin`，可用
`prof.sec_fetch_site` 覆盖）。

`describe()` 里的 `header order : navigate=reference, xhr=derived` 会告诉你两套模板
各自是哪来的。

HEADERS 帧的优先级也是分 kind 的：导航 weight=256，**XHR 是 220**（实测），后者只有
reference 提供时才知道。

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
  或者换 `prof.header_profile = "xhr"`。

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

用哪一套由 `Profile.hpack` 决定，见上面[加一个浏览器](#加一个浏览器)。

---

## 三档可信度

本目录的改动分三档，**收益依据的强度差别很大**，别当成同等重要。

### 第一档：进指纹哈希的 —— 有实证

只有两样：

* **TLS 层**（JA3 / JA4 / peetprint）—— 由 C 库负责，本目录不涉及
* **akamai 指纹** —— SETTINGS、连接级 WINDOW_UPDATE、PRIORITY、**伪头**顺序，
  就这四段

这两样能对着 `profiles/` 里的真浏览器抓包逐字段比对，对上就是对上了。akamai 这四段
如今是直接从抓包读的，不是照着源码抄进代码的常量 —— 抄错的可能性被去掉了。

### 第二档：header 的集合 —— 逻辑上站得住，但不进任何哈希

**普通 header（名字、值、顺序）不在上面任何一个哈希里。** 可以自己验证：

```python
# 把 header 砍到只剩 3 个、顺序打乱、UA 改成 totally-not-chrome/1.0
# → ja4 和 akamai_fingerprint_hash 一个字符都不变
```

实测确认过。所以 header 模板对"指纹哈希"的贡献是**零**。

它的价值在别处：一个请求 UA 写着 `Chrome/150`，却没有 `sec-ch-ua`、没有 `sec-fetch-*`、
没有 `accept-language`，这本身是自相矛盾的，一条规则就能判掉，不需要什么指纹库。
模板真正的作用是——**你什么都不传就得到一套自洽的浏览器头**。这一档我认为价值是实的。

### 第三档：header 顺序 与 HPACK 字节 —— 做到了，但收益无实证

* **header 顺序**：反爬会校验 header order 这个说法在业内材料里很常见，但
  **本项目没有验证过任何一家真的在查**。既然已经在构造这个列表，顺手排对不额外花钱。
* **HPACK 字节**：那四处编码策略对齐（条件 huffman、不发 never-indexed、伪头不进动态表、
  cookie 拆分）确实做到了和真 Chrome **逐字节相同**（455 字节，见下方验证），这是事实。
  但**有没有人真的去哈希 HEADERS 的原始字节，没有任何证据**，实际收益可能接近于零。

留着的理由是成本而非收益：代码已写好、运行时开销为零、已验证不破坏功能。
如果觉得维护负担不值（尤其 `sec-ch-ua` 跨大版本要重新抓包这一条），
删掉 `_build_headers` 和 `_QuicheEncoder`、只保留 SETTINGS/WINDOW_UPDATE/priority，
akamai 和 TLS 照样全对。

---

## 验证

三层都有真实浏览器参照，全部验证通过。**注意这里的"通过"只对第一档构成指纹证据**，
第二、三档是"与真浏览器一致"，不等于"有人在查"。

### 新机器上怎么确认构建是对的

`install-python.sh` 自带两道，装完自动跑，**都不需要外网**：

| | 查什么 | 失败表现 |
|---|---|---|
| 链接检查 | CLI 与 Python 加载的 libssl 是不是 `$PREFIX/lib` 里那个 | 直接 `die` |
| 自检 | 本机起 h2 服务器，自己连自己，把 **ClientHello + h2 帧 + HPACK 字节**和 `profiles/` 里**每个** brand 逐项比 | 打出 diff 后 `die` |

第二道单独跑就是：

```bash
python hpack_probe.py selftest                  # 所有 brand
python hpack_probe.py selftest --brand chrome   # 只跑一个
```

服务器和客户端都在同一个进程里（服务器跑在线程里），不需要开两个终端，也不需要外网。

它对端口敏感（`:authority` 里带端口），所以端口是从参考抓包里读出来的，**不能随便改**：

```bash
python hpack_probe.py port chrome    # → 8443
```

要跳过用 `--skip-selftest`，但那样就没有任何东西检查过指纹了。

**不要拿 OpenSSL 自带的 `make test` 当验收标准。** 这个 fork 钉死了 cipher 列表、
sigalgs 和证书压缩算法，`test_ssl_new` 里有 14 个配置因此必然失败（含
`04-client_auth`、`26-tls13_client_auth`）—— 那是改造的**代价**，不是 bug。真要用它
做回归，得和改动前的 commit 跑同一组测试、比**失败集合是否一致**，而不是看有没有失败。

联网之后再跑一次 `verify_fp.py`（见下），那是唯一能证明"真实服务端也认"的检查。

### TLS + h2 帧 + 头（联网）

```bash
python verify_fp.py                    # TLS(无 PSK) + 完整 h2 层
python verify_fp.py --resume           # TLS 含 PSK，对应参考文件的场景
python verify_fp.py --brand chrome     # 装了多个 brand 时指定
```

基准是 `references/<brand>.json`，抓包时自动存的。没有 peet 那半会直接报错退出，
不会拿别的 brand 的去比。有 `ja3zone` 那半时会多跑一段：**再问一次 check.ja3.zone**，
把它算的 JA3 哈希和真浏览器的比——这是和 peet 完全独立的第二套实现。

它还会按 reference 自动对齐 `accept-language`、`cache-control`、`sec-fetch-site`
和 `referer`，所以 `referer` 的位置是真的被验证到的，而不是只在代码里写对。
`--xhr` 换成拿 cors 那份比，验的就是 xhr 模板（含 weight 220）。

**JA3 那段不比哈希。** JA3 把扩展列表按**线上顺序**哈希，而 Chrome 从 110 起每条连接都
打乱扩展顺序 —— 真 Chrome 自己两次连接的 JA3 也对不上。实测我们和参考的扩展**集合完全
相同、顺序不同**。所以比的是版本、cipher 列表、**排序后的**扩展集合、curves、点格式，
哈希只打印不判定。（JA4 排过序，所以 peet 那边的 ja4 是能直接比的。）

**这一步查的是 selftest 查不到的东西。** ClientHello 永远没法逐字节比 —— client random、
key_share 公钥、session id、GREASE 值、扩展顺序每次都变，所以 selftest 只能比"形状"，
而形状是我按自己的理解定义的。peet 那份是**第三方独立算出来的哈希**，能抓到"自己验自己"
的盲区；`--resume` 那条路径（PSK 扩展）离线更是完全测不了，我们的探针不发 session ticket。

顺带一提：自动存的 reference 是浏览器 `fetch()` 发的，属于 XHR 而非导航，所以
`verify_fp.py` 看到 `sec-fetch-mode: cors` 会自动切到 `xhr` 模板 —— 这也是目前唯一
能拿真浏览器验证 `xhr` 模板的场合。

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

`selftest` 会把这两样和 `profiles/<brand>.json` 逐项比：ClientHello（record/legacy 版本、
session_id 长度、cipher 列表、每个扩展的类型与 body 长度；GREASE 的**值**通配掉，因为它
本来就该每连接都变，但**长度**不通配），然后 h2 帧层，最后 HPACK 逐字节。

只比第一个 HEADERS 帧：HPACK 动态表有状态，只有连接刚建立时两边都是空表才可比。

当前结果：ClientHello 七项全 OK，h2 五项全 OK，HPACK **455 字节完全相同**。

扩展**顺序**不参与比较 —— Chrome 和我们都是每连接随机打乱的，只有集合、每项的 body
长度、以及首尾两个位置（GREASE 固定在最前、倒数第二）才是形状的一部分。

要手工比两个文件，`diff` 收路径也收 brand 名：

```bash
python hpack_probe.py serve --out /tmp/ours.json &   # --out：不注册成 brand
python hpack_probe.py client --brand chrome
python hpack_probe.py diff chrome /tmp/ours.json
```

自签证书和临时文件落在 `~/.cache/hpack_probe/`，不进仓库；
`HPACK_PROBE_DIR` 可改。

---

## 两个会变的头

抓包时发现这两项 Chrome 自己就不固定，别当成常量：

* **`cache-control: max-age=0`** —— 刷新或地址栏回车重进时发，**全新地址导航不发**。
  两种情况都在真实抓包里见过。开关是 `prof.send_cache_control`。
* **`accept-language`** —— 跟浏览器的界面语言走，默认就是抓包时的那个值
  （当前 `chrome` 抓包是全新 profile，`en-US,en;q=0.9`）。

`verify_fp.py` 会自动按 `references/<brand>.json` 里实际发的头对齐这两项，
不用手动设。

---

## 已知不做 / 注意

* **`xhr` 模板的顺序只在有 reference 时才是实测的。** 没有 reference 的 brand 用的是
  从 navigate 改写出来的推断顺序；实测表明真 XHR 会把 client hints 拆到 `user-agent`
  两侧，和推断的不一样。抓包时能拿到 peet 那半就没这个问题。
* **SETTINGS GREASE 不模拟。** Chrome 能发第五个 GREASE 设置，但 id 和值都是每连接随机，
  且 `enable_http2_settings_grease` 默认关。网上流传的固定值本身就是特征 —— 真抓到一个
  发 GREASE 的客户端，那个随机值会被当成常量存进 profile，反而更糟，抓完看一眼
  `catalog()`。抓包里若出现独立 PRIORITY 帧，加载时会告警 —— 那一段不复现。
* **HPACK 引擎只实现了 quiche 一套。** 非 Chromium 的 brand 默认退回 hpack 原样，
  字节层大概率对不上（`selftest` 会告诉你），但 akamai 和 TLS 不受影响。
* **这是对 httpcore 内部类的子类化。** httpcore 把 HTTP/2 类的 import 写在
  `handle_request()` 函数体里，没有钩子可用，所以改的是**赋值那一步**：给连接对象
  的 `_connection` 装一个 property，它在 httpcore 刚建好 `HTTP2Connection`、还没发
  preface 时把它改挂成我们的子类。好处是**一行 httpcore 的连接逻辑都没抄**，直连、
  代理隧道、SOCKS 三条路径共用同一个钩子。httpx/httpcore/h2 版本一变仍可能失配，
  建 transport 时会校验并告警。升级前请重跑上面全部验证。
* **只覆盖 h2。** `httpx.Client()`（http/1.1）没有 SETTINGS 那种指纹面，只剩头顺序，
  但本模块的头模板只作用于 h2 路径。
