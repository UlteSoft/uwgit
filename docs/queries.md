# 已提交树、引用、对象与远端广告查询

新增 `ls-tree`、`show-ref`、`for-each-ref`、`count-objects` 和 `ls-remote`。接口参考 Git 官方的 [ls-tree](https://git-scm.com/docs/git-ls-tree)、[show-ref](https://git-scm.com/docs/git-show-ref)、[for-each-ref](https://git-scm.com/docs/git-for-each-ref)、[count-objects](https://git-scm.com/docs/git-count-objects) 和 [ls-remote](https://git-scm.com/docs/git-ls-remote)；下述选项是本程序实际支持的子集，不表示 Git 对象格式或协议兼容。

## 本地查询

```sh
wasm-git ls-tree DIR REV [-r] [--json | --name-only | --object-only] [-z] [-- PATH...]
wasm-git show-ref DIR [--head] [--heads|--branches] [--tags] [--verify] \
  [--quiet|-q | --hash | --json] [PATTERN...]
wasm-git for-each-ref DIR [--json | --format STR] [--sort KEY]... [--count N] [PATTERN...]
wasm-git count-objects DIR [-v|--verbose] [-H|--human-readable]
```

每个命令只读取一次经验证的仓库快照，临时使用现有 writer 锁协调其他写入；退出后不保留锁或修改文件。对象、引用、upstream、fetched tracking 与 reflog 的损坏明确失败，不修复。index、pending 和工作文件不参与已提交对象查询，因此未完成的编辑、损坏的 index/pending、缺失工作文件不会阻止查询。未知选项、无效模式、格式和数值在打开仓库前拒绝；帮助也不访问仓库或网络。

`ls-tree` 默认 JSON 包含实际 commit/tree ID 和逐文件的 Wasm blob ID、payload 长度与完整存储 envelope 长度。仓库存储平面路径映射；`-r` 因此返回同一份完整路径，不合成目录对象、目录 ID、Unix mode 或可执行位。接受现有 commit 修订语法或完整 tree ID；不把 tree 前缀猜成修订。`-- PATH...` 可选精确文件、目录后代或 `.`，每个选择器必须匹配。尾斜线只匹配目录后代，`a.wasm/` 不能匹配同名文件；路径选择现共享 [pathspec](head-and-pathspec.md)：支持单个前导 `./`、glob/literal/icase/top/exclude，仍拒绝内部 `.`/`..`。文本模式输出原始 UTF-8，`-z` 使用 NUL 且不额外添加 LF。旧 unnamed 单模块提交仅在 JSON 的 `legacy` 字段保留其真实 blob 证据；不从 index 猜文件名，亦不把它作为空命名树。

`show-ref` 默认逐行 `ID SPACE full-ref LF`，包含本地 branches/tags 和 fetched tracking branches。普通 pattern 是路径组件边界上的字面后缀，多个 pattern 取并集。`--head` 单独加入实际 HEAD，不受普通 pattern 或 heads/tags 筛选影响；unborn HEAD 不生成 ID。`--verify` 只接受完整引用或 HEAD，按请求顺序输出，忽略 namespace 筛选；任一缺失时不输出部分结果。无匹配退出 1，JSON 此时仍提供空 refs 与 HEAD 元数据；quiet 缺失时 stdout/stderr 均空。quiet、hash、json 三种显式输出互斥。

`for-each-ref` 默认逐行 `ID SPACE kind TAB full-ref LF`，不加入 HEAD 行。字面 pattern 按完整引用前缀及 slash 边界匹配；含通配符时按完整引用使用 `*`/`?`。不支持 brackets 或反斜杠转义，模式限 1,024 字节。无匹配退出 0。sort 支持 refname/objectname/objectsize，objectsize 是 payload 字节；可加 `-` 降序，多次 sort 的最后一个是主键，其余按稳定排序保留。count 0 不限行数。

format 支持 `%(refname)`、`%(objectname)`、`%(objecttype)`、`%(objectsize)`、`%(HEAD)` 和 `%(upstream)`；当前 branch 的 HEAD atom 为 `*`，其他为一个空格。upstream 输出完整 `refs/remotes/REMOTE/BRANCH`，未配置时为空。支持 `%%` 与 ASCII `%00` 至 `%7f`，可含 NUL，每行末尾仍加 LF；其他文字可直接写 UTF-8。未知 atom、modifier 或非 ASCII hex escape 明确拒绝，format 总长限 64 KiB。JSON 与 format 互斥。两个引用查询的 JSON 均为 `{schema_version, head, head_tip, refs:[...]}`。

`count-objects` 默认 JSON 按实际唯一对象统计，分别报告 payload 与未压缩 envelope 的逻辑长度。`-v` 加各 kind 的数量与长度，`-H` 加 B/KiB 等可读长度；不把它们称作文件系统分配空间，也不虚报 Git pack。reachable 的根为本地 branches/tags、detached HEAD、fetched tracking **branches** 和共享/本地 HEAD reflog 的 old/new commits；不包括 remote-only cached tags、index 或 pending 未发布进度，`root_policy` 明示这一规则。它和 fsck 的 local refs 加 detached HEAD 统计不同；unreachable 只是上述规则的观察，不能用来决定删除。

## HTTP 与 SSH 远端广告

```sh
wasm-git ls-remote URL [OPTIONS] [PATTERN...]
wasm-git ls-remote DIR [REMOTE] [OPTIONS] [PATTERN...]
```

只支持既有 HTTP(S)/SSH URL；DIR 单独使用时选择 origin。若筛选默认 remote，明确写 `DIR origin PATTERN`，第二个位置不会猜成 pattern。支持 `--heads|--branches`、`--tags`（两者并集）、`--refs`、`--symref`、`--exit-code`、`--json` 和现有 `--allow-insecure-http`。`--` 结束选项识别。未知或重复选项明确失败。

默认输出 `ID TAB full-ref LF`，包含有实际 ID 的 HEAD、branches 和 tags；`--refs` 去掉 HEAD。模式使用 `*`/`?`，匹配完整引用或任意 slash 后的后缀。`--symref` 可输出 `ref: refs/heads/NAME TAB HEAD LF`；unborn 时该符号行也可存在，但不虚造 ID。`--exit-code` 在没有匹配的**实际 ID 行**时返回 2，因此可能输出一条 unborn 符号行同时退出 2。

查询只发一次空 payload 的 Advertise 请求，拒绝返回对象 payload、更新 tip、损坏 state 或协议 envelope。不执行 fetch，不建立仓库、不创建 remotes 目录或 tracking。配置模式仅读有界 regular config，不依赖坏 index/pending/本地 objects/tracking，也不取得写入或配置锁。复用现有 transport 的 URL、token、明文限制、超时与 framing 验证。JSON 单独标明 `advertised_only:true`、`objects_verified:false`、`unverified_objects:true`；远端提供的 ID 不等于已下载并验证的对象，不虚报 object kind/size。
