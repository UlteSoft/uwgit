# HTTP 与 SSH 服务

`wasm-git server` 为同一服务根目录下的多个 uwgit 仓库提供读取及受控引用更新。
每个子目录是一个独立仓库；服务不执行 Wasm。客户端和服务端使用 uwgit 的对象及 RPC 格式。

## HTTP

```sh
mkdir -p /srv/uwgit
wasm-git init /srv/uwgit/project
wasm-git server --root /srv/uwgit --listen 127.0.0.1:9419
wasm-git clone http://127.0.0.1:9419/project ./peer
```

默认监听 loopback，默认只读。写入服务使用管理员提供的 token 文件：

```sh
wasm-git server --root /srv/uwgit --listen 127.0.0.1:9419 \
  --token-file /run/secrets/uwgit-token --allow-write
export UWGIT_REMOTE_TOKEN='your-token'
wasm-git remote ./peer add origin http://127.0.0.1:9419/project
wasm-git push ./peer origin main:main
```

示例 token 须自行替换。token 为 1–4096 个无空白的可打印 ASCII 字节，文件可有一个末尾换行。
服务配置 token 时，读取和写入请求均需 Bearer 认证。客户端不会保存 token 到 remote 配置，
不会将其放入 curl 的命令行参数；临时 header 文件仅当前用户可读，并在操作结束后删除。
每个客户端操作直接连接指定地址；不自动重定向，不读取 curlrc，也不使用代理环境配置。

外部网络使用 HTTPS 反向代理连接 loopback HTTP 服务，客户端验证正常 TLS 证书。
`server` 本身没有 TLS 终端。HTTP 远端使用明文认证需显式
`remote DIR add NAME URL --allow-insecure-http`；loopback 测试不需要此选项。
`--allow-force` 由管理员另行开启，客户端还必须提供准确的 `--force-with-lease OLD_ID`。

## SSH

在服务机器安装 `wasm-git`，使用既有 OpenSSH 用户及密钥授权：

```sh
wasm-git clone ssh://alice@example.org/srv/uwgit/project ./peer
wasm-git remote ./peer add origin ssh://alice@example.org/srv/uwgit/project
wasm-git fetch ./peer origin
wasm-git pull ./peer origin main -m 'integrate remote'
wasm-git push ./peer origin main:main
```

URL 的绝对路径父目录成为服务根，最后一段为仓库名。客户端调用
`ssh -T ... -- USER@HOST 'wasm-git server --stdio --root ...'`，通过标准输入输出交换单个请求。
服务端使用 SSH 的系统用户权限，stdio 默认允许写入；HTTP token 不会转发给 SSH。
远端程序及路径逐项 shell 引用，客户端不将输入拼接成未引用的 shell 命令。

`UWGIT_REMOTE_PROGRAM` 可指定远端单个可执行文件路径，`UWGIT_SSH_PROGRAM` 可指定本机单个 SSH
可执行文件或包装脚本。两者都不是 shell 命令字符串。主机密钥遵守 OpenSSH 的正常策略，
连接使用 BatchMode，不会挂起等待交互密码。
允许 SSH 强制推送时，管理员可提供包装程序，在接收 `server --stdio` 参数时加入
`--allow-force`。SSH 账户或 forced-command 的授权范围由部署管理员配置。

## 多个 Wasm 文件

远端传输提交中的完整文件树，每个路径对应一份原始 Core Wasm 字节。
路径、空树、文件新增和删除都是提交内容；服务不会把多个模块合并成一个 Wasm，
也不会通过文件内容相同来猜测重命名。

```sh
wasm-git add ./work modules/client.wasm modules/server.wasm
wasm-git commit ./work -m 'track both modules'
wasm-git tag ./work base
wasm-git remote ./work add origin https://example.org/project
wasm-git push ./work origin
wasm-git push ./work origin --tags
wasm-git clone https://example.org/project ./peer
wasm-git restore ./peer --source HEAD --staged --worktree
wasm-git show ./peer HEAD --file modules/client.wasm --output /tmp/client.wasm
wasm-git diff base HEAD --repo ./peer --file modules/client.wasm --format json
```

`clone` 保存完整历史及所有分支、标签，随后可以显式恢复工作文件。
`fetch` 更新独立的 remote tracking，不改变本地分支、暂存内容或工作文件。
默认 tree diff 逐路径报告新增、删除、修改和未变；`--file PATH` 可选择单个模块。
删除最后一个暂存路径后仍可提交空树，空树也能正常推送和克隆。

两个客户端产生文件树冲突后，可以用完整暂存树显式保存解决结果及两个父提交：

```sh
wasm-git merge ./peer IMMUTABLE_TARGET_ID -m 'review complete resolved tree' \
  --resolved-index --expect-head IMMUTABLE_HEAD_ID
wasm-git push ./peer origin
```

这条手工命令精确使用已存在的暂存树，不改暂存区或工作文件；未暂存的修改仍保留。
真实的空暂存树表示删除所有路径，缺少暂存区则拒绝。文件变目录、目录变文件都按实际路径删除和新增传输，
不会推测重命名。响应逐文件保存 base、两个父版本和解决结果的原始字节与审计，显式选择的未知特性仍会标记。
另一客户端 `fetch` 仍只更新 tracking，随后 `pull` 才将干净的受跟踪工作文件同步到所接收的完整树。

RPC 帧和广告状态继续使用 version/format 1。文件树位于 bundle 内部：
Tree 对象为 kind 3，tree commit 为 format 2，包含这些对象的 bundle manifest 为 format 3。
接收端先校验完整对象图、规范路径和每个 blob 的对象摘要，再安装对象或更新引用。
非法路径、缺失 blob、对象类型错误和损坏对象均会拒绝；不支持新对象格式的版本也会明确拒绝。
所有文件的编码、名称和原始字节都受 bundle 校验约束，64 MiB 的帧上限同样适用于多文件传输。

完整快照按依赖顺序发布：先 Wasm blob，再 tree，最后按父先子后的顺序安装 commit，不能按对象 ID 排序代替依赖顺序。
本地 clone、bundle/网络 clone、unbundle、fetch 安装和服务端 receive 共用此规则，
并保留完整快照中合法的不可达对象与历史。对象安装中断可留下未引用但闭包完整的对象，
引用在所需对象完整安装前不发布；重试仍可验证已有存储，不需要先删除合法 dangling 对象。
这不表示多个引用与 reflog 具有跨文件断电事务，最终发布或同步失败仍按实际完成范围报告。

## 一致性与失败结果

`fetch` 安装已校验对象并保存 remote tracking，保留本地分支。
`clone` 保存所有 advertised 分支、标签和 unborn HEAD。
fetch 网络交换前记录完整的可选 tracking 基线，安装对象后在 remote 配置锁内同时核对配置和整条基线，
再原子保存新 tracking。比较包括记录缺席、HEAD、全部分支和标签，而非仅比较某一分支 tip 或祖先关系。
并发 fetch 若已先发布新状态，延迟旧响应会明确报错，保留最新 tracking；已安装对象保留，本地分支、index 和工作文件不变。
后续独立 fetch 仍能接受远端合法的强制回退。固定并发与中断回归。
push 绑定 advertised 旧提交或“引用不存在”；服务端在仓库锁内重新检查旧值。
普通分支推送只允许快进，已有标签不能被普通推送替换。
标签替换需要显式租约及服务端 force 许可，删除也要核对旧引用。
服务端拒绝删除当前 HEAD 分支。

`push DIR origin --tags` 为逐标签更新，每项单独校验和发布。返回值逐项报告成功、未变化或失败，
任何失败均非零退出，可能已经发布前面的标签；不声称批量原子性。
响应丢失时客户端不能据此断言服务端未发布，应重新 fetch/advertise 检查。
RPC 的 `publication_unknown` 单独标记进入引用发布阶段后的不确定失败；
客户端不会将这种错误当作已拒绝，批量标签操作会停止后续更新。
磁盘写入失败可能留下合法的未引用对象，引用不会在输入校验或租约检查完成前更新。
ref 已发布后同步或 reflog 写入失败会明确报告已发布状态。

服务根、仓库路径及 token 路径拒绝符号链接与 `..`。
服务端持有暂存锁后检查当前分支：有 tracked index 的当前分支拒绝远端更新，
避免覆盖用户正在使用的工作文件。服务仓库通常只保存对象和引用，不维护 tracked 工作文件。
仓库锁保护遵守同一协议的协作进程；操作系统账户对目录的任意外部替换不受其保护。

## 线格式与资源界限

HTTP 仅接受 `POST /v1/uwgit`，关闭每次连接，要求唯一的 `Content-Length`，拒绝
`Transfer-Encoding`、重复 header、超限 header 及不完整输入。HTTP 请求格式依据
[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html) 的 framing 规则。
请求中的 repository 指定服务根下的一个受限简单名称，URL 路径不用于拼接任意文件名。
客户端与服务端共用仓库名称检查，可用 `project.git` 等带点名称，最多 128 个 ASCII 字节；
remote 配置名仍使用独立的 64 字节限制。

HTTP body 与 SSH stdio 使用同一帧：

| 字段 | 编码 |
|---|---|
| magic | 8 字节 `UWGRPC01` |
| metadata length | u32 大端，1–65536 |
| payload length | u64 大端，转换为本机长度前检查 |
| metadata | 严格 JSON，拒绝未知字段 |
| payload | 完整原始 bundle，或空 |

完整帧最多 64 MiB，帧之后的尾随内容拒绝。
metadata version 为 1，操作为 advertise、fetch、push 或 update_ref。
push 的 expected、update_ref 的 expected 和 new 必须显式出现；JSON null 分别表示预期引用不存在或明确删除，
省略字段会拒绝整个请求，不能隐式请求删除。
push/update_ref 只发布明确指定的一条引用，bundle 中其他分支及标签不会被隐式更新。
HTTP header 最多 16 KiB，连接有总时限，最多同时运行 16 个连接 worker。
`--max-connections N` 供有限集成测试使用，生产服务默认持续监听。

本协议没有压缩 pack、增量协商、签名或 Git smart HTTP/upload-pack/receive-pack 兼容层。
对象完整性来自原始编码的 SHA-256；认证只证明运输层授权，不能证明提交作者身份。
