# Agent Note：归一化 `/api` Host 时按 Origin 所指的 scheme 读取，并说明是哪一道检查拒绝了请求

Status: implemented

[English](2026-08-26-api-trust-origin-scheme-normalization.md) | 中文

## 问题

`/api` 权威栅栏（[api 浏览器信任边界](../architecture/2026-07-28-api-browser-trust-boundary.zh.md)）在把附带的 `Origin` 与 `Host` 比较时，两侧都经 WHATWG 归一化——但 `Host` 始终按固定的 `http:` 读取。`Host` 请求头所指的权威自身不带 scheme，因此该权威的默认端口是哪一个，只能由它旁边的 `Origin` 得知。按固定的 `http:` 读取时，`:443` 不是默认端口，会在归一化后保留，而浏览器的 https `Origin` 会把它丢掉：任何把默认端口写全的 TLS 终结器都会送出 `Host: name:443` 配 `Origin: https://name`，于是每个 `/api` 请求都被拒绝，连 UI 要显示任何内容都必需的 WebSocket 握手也在内。

这种拒绝同样无从诊断。所有失败都只回一个光秃秃的 `forbidden`，运维只看得到 `transport failure for /api/host.pickDirectory: HTTP 403`，无法区分被改写的 `Origin`、未声明的权威、以及特权方法的回环钉住——三种成因对应三种不同的处理方式，其中一种（`--trusted-host`）根本解不开这道钉住。钉住的症状尤其容易误导：`/api` 的其余部分都正常，部署看上去是健康的，只有目录选择器像是坏了。

## 决策

按 `Origin` 所指的 scheme 归一化两侧权威。当且仅当 `Origin` 是 https 时，`Host` 按 `https:` 重新读取，于是当前 scheme 的默认端口不参与信任判定，而任何非默认端口仍然参与：`127.0.0.1:3080` 对 `http://127.0.0.1` 依旧被拒，跨端口在两个方向上都仍然关闭。`http:`/`https:` 之外的 `Origin` 现在直接拒绝而不再参与比较：本服务端送出的页面必定是这两者之一，WHATWG 解析器不会归一化非特殊 scheme，而旧的比较会让 `app://127.0.0.1:3080` 与该 `Host` 匹配通过。

栅栏现在给出裁定而不是布尔值。`describeApiRequestTrust` 返回拒绝原因（封闭的 `ApiTrustRefusal` 标签）与一行诊断，并且每一个 403——HTTP 路由、共享通道拦截器、WebSocket upgrade 拒绝——都会带上它。因回环钉住而被拒的特权方法会直说这一点，而不是重复"用 `--trusted-host` 声明该权威"这条通用建议——它并不会放宽特权方法集合。谓词 `isTrustedApiRequest` 已无调用方，随之删除。

诊断只回显调用方自己送来的请求头。403 响应体中不会出现任何已配置的 `trustedHosts` 条目：被拒的调用方只会得知自己哪个请求头没通过，而不会得知该部署信任什么。

## 备选方案

- **当 Host 是回环地址时，忽略端口比较两侧权威。** 否决：这会让 `http://127.0.0.1`（服务在 80 端口的页面）的 `Origin` 与 `127.0.0.1:3080` 的 `Host` 匹配通过，恰好在回环接口上打开那个被报告归咎于"`Origin` 被改写"的跨端口漏洞。改写是客户端的缺陷；为了迁就它而放松栅栏，是拿一条真实边界去换一个绕行办法。
- **信任 `X-Forwarded-Proto` 来判断 scheme。** 否决：在没有代理剥离该请求头的地方，它由攻击者控制，而对这道比较真正涉及的请求而言，`Origin` 本身已经权威地给出了 scheme。
- **在服务端记录拒绝原因，响应体维持原状。** 否决：读到浏览器传输错误的运维，通常并不是读服务端 stdout（标准输出）的那个人，而且这道栅栏所在的插件目前没有 logger 注入。响应体本就只会送达能复现该请求的人。
- **为已声明的权威解开特权方法的回环钉住。** 否决：这超出本次范围，本记录也未改动它——这道钉住要等真正的认证层，与其归属的架构记录所载完全一致。本次改动只是让钉住把自己说清楚。

## 影响

- 位于把 `:443` 写全的 TLS 终结器之后的部署现在可以正常工作，而不再对每个 `/api` 请求回 403；此前能通过栅栏的一切仍然通过。
- `http:`/`https:` 之外的 `Origin` scheme 由"参与比较"变为"直接拒绝"。已发布的客户端都不会送出这类 `Origin`——浏览器载体经 http(s) 提供，进程内载体不经过这道栅栏。
- 403 响应体现在是可变文本。`packages/client/connection/tests/node-half.host.spec.ts` 断言的是确切的诊断文本，而非旧的字面量 `forbidden`：对一个可自我诊断的拒绝来说，响应体正是这道栅栏面向用户的契约。
- `rejectWebSocketUpgrade` 将诊断作为必需参数，于是两种传输以同一套措辞拒绝请求。
