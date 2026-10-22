# 已提交树、引用、对象与远端广告查询

新增 `ls-tree`、`show-ref`、`for-each-ref`、`count-objects` 和 `ls-remote`。接口参考 Git 官方的 [ls-tree](https://git-scm.com/docs/git-ls-tree)、[show-ref](https://git-scm.com/docs/git-show-ref)、[for-each-ref](https://git-scm.com/docs/git-for-each-ref)、[count-objects](https://git-scm.com/docs/git-count-objects) 和 [ls-remote](https://git-scm.com/docs/git-ls-remote)；下述选项是本程序实际支持的子集，不表示 Git 对象格式或协议兼容。

## 本地查询

```sh
wasm-git ls-tree DIR REV [-r] [--json | --name-only | --object-only] [-z] [-- PATH...]
wasm-git show-ref DIR [--head] [--heads|--branches] [--tags] [--verify] \
  [--quiet|-q | --hash | --json] [PATTERN...]
wasm-git for-each-ref DIR [--json | --format STR] [--sort KEY]... [--count N] \
  [--contains [REV]] [--no-contains [REV]] [--merged [REV]] [--no-merged [REV]] \
  [--points-at OBJECT] [--exclude PATTERN]... [--ignore-case] [--omit-empty] [PATTERN...]
wasm-git branch DIR --list [-r|-a] [--contains [REV]] [--no-contains [REV]] \
  [--merged [REV]] [--no-merged [REV]] [--points-at OBJECT] \
  [--ignore-case|-i] [--sort KEY]... [--format STR|--json] [--omit-empty] [--] [PATTERN...]
wasm-git branch DIR --show-current
wasm-git count-objects DIR [-v|--verbose] [-H|--human-readable]
```

每个命令只读取一次经验证的仓库快照，临时使用现有 writer 锁协调其他写入；退出后不保留锁或修改文件。对象、引用、upstream、fetched tracking 与 reflog 的损坏明确失败，不修复。index、pending 和工作文件不参与已提交对象查询，因此未完成的编辑、损坏的 index/pending、缺失工作文件不会阻止查询。未知选项、无效模式、格式和数值在打开仓库前拒绝；帮助也不访问仓库或网络。

`ls-tree` 默认 JSON 包含实际 commit/tree ID 和逐文件的 Wasm blob ID、payload 长度与完整存储 envelope 长度。仓库存储平面路径映射；`-r` 因此返回同一份完整路径，不合成目录对象、目录 ID、Unix mode 或可执行位。接受现有 commit 修订语法或完整 tree ID；不把 tree 前缀猜成修订。`-- PATH...` 可选精确文件、目录后代或 `.`，每个选择器必须匹配。尾斜线只匹配目录后代，`a.wasm/` 不能匹配同名文件；路径选择现共享 [pathspec](head-and-pathspec.md)：支持单个前导 `./`、glob/literal/icase/top/exclude，仍拒绝内部 `.`/`..`。文本模式输出原始 UTF-8，`-z` 使用 NUL 且不额外添加 LF。旧 unnamed 单模块提交仅在 JSON 的 `legacy` 字段保留其真实 blob 证据；不从 index 猜文件名，亦不把它作为空命名树。

`show-ref` 默认逐行 `ID SPACE full-ref LF`，包含本地 branches/tags 和 fetched tracking branches。普通 pattern 是路径组件边界上的字面后缀，多个 pattern 取并集。`--head` 单独加入实际 HEAD，不受普通 pattern 或 heads/tags 筛选影响；unborn HEAD 不生成 ID。`--verify` 只接受完整引用或 HEAD，按请求顺序输出，忽略 namespace 筛选；任一缺失时不输出部分结果。无匹配退出 1，JSON 此时仍提供空 refs 与 HEAD 元数据；quiet 缺失时 stdout/stderr 均空。quiet、hash、json 三种显式输出互斥。

`for-each-ref` 默认逐行 `ID SPACE kind TAB full-ref LF`，不加入 HEAD 行。字面 pattern 按完整引用前缀及 slash 边界匹配；含通配符时按完整引用匹配：`*`/`?` 不跨 slash，完整 `**` 组件可跨目录。不支持 brackets 或反斜杠转义，模式限 1,024 字节。多个包含模式取并集；重复的 `--exclude` 按同一规则排除任一匹配。`--ignore-case` 对名称筛选、排除及字符串排序采用 ASCII 大小写折叠，保留原名称输出。无匹配退出 0。

format 支持 `%(refname)`、`%(objectname)`、`%(objecttype)`、`%(objectsize)`、`%(HEAD)` 和 `%(upstream)`；当前 branch 的 HEAD atom 为 `*`，其他为一个空格。upstream 输出完整 `refs/remotes/REMOTE/BRANCH`，未配置时为空。refname/upstream 支持 `:short`、`:lstrip=N`／`:strip=N` 和 `:rstrip=N`。正数从指定端剥离组件，负数表示保留该数量的另一端组件，超出组件数时分别得到空串或完整名称。N 为有符号 64 位整数，最小负值及超过 32 位范围的值在双架构上有相同的有界行为。

short 按 uwgit 的实际解析规则检查完整快照中的 branches、tags、tracking 和已存提交前缀；名称筛选和图筛选不会让被隐藏的歧义消失。若简称仍有歧义，输出完整 `refs/...`，不输出 uwgit 尚不能解析的 Git `heads/...` 等缩写。已失效 upstream 仍有配置名称，不能缩写成另一个本地分支。不会从工作文件或索引生成引用。

支持 `%%` 与 ASCII `%00` 至 `%7f`，可含 NUL，每行末尾仍加 LF；其他文字可直接写 UTF-8。`--omit-empty` 省略格式展开为空的整行，空格或 NUL 均不算空串。未知 atom、modifier 或非 ASCII hex escape 明确拒绝，format 总长限 64 KiB。JSON 与 format/omit-empty 互斥。sort 支持上述 atom 和名称 modifier；objectsize 按实际 payload 字节数值排序，其余为字符串，可加 `-` 降序，多次 sort 的最后一个是主键。默认按完整 refname，等值保持原全名次序。count 是无符号 64 位整数，0 不限行数，超出实际行数时有界截取；在格式与 omit-empty 之前计数。引用查询的 JSON 仍为 `{schema_version, head, head_tip, refs:[...]}`。

`count-objects` 默认 JSON 按实际唯一对象统计，分别报告 payload 与未压缩 envelope 的逻辑长度。`-v` 加各 kind 的数量与长度，`-H` 加 B/KiB 等可读长度；不把它们称作文件系统分配空间，也不虚报 Git pack。reachable 的根为本地 branches/tags、detached HEAD、fetched tracking **branches** 和共享/本地 HEAD reflog 的 old/new commits；不包括 remote-only cached tags、index 或 pending 未发布进度，`root_policy` 明示这一规则。它和 fsck 的 local refs 加 detached HEAD 统计不同；unreachable 只是上述规则的观察，不能用来决定删除。

## 原生提交图筛选与分支列表

`--contains REV` 选择其 tip 的祖先闭包包含 REV 的引用；`--merged REV` 选择 tip 位于 REV 祖先闭包中的引用。`--no-contains`／`--no-merged` 排除对应关系。每个家族重复正向条件取并集，负向条件排除全部匹配，四个家族之间取交集。遍历包含所有真实父边，不把 merge 简化为 first-parent。省略 REV 默认实际调用工作树的 HEAD，unborn HEAD 明确失败。条件解析为实际 commit ID，复用原生修订语法；不接受 Wasm/tree 作为祖先条件。

`--points-at OBJECT` 选择实际 tip 等于给定对象的引用，重复值取并集。它复用原生对象查询语法：commit 修订、完整 ID、各类型唯一对象前缀、tree peel 和命名模块路径；有效 Wasm/tree 对象可作为输入，但当前引用只能指向 commit，因此输出为空。未知或歧义输入失败。

全部图条件、引用、upstream、tracking 和名称歧义在同一个经过校验的快照中确定。即使名称没有匹配，也不掩盖坏修订或仓库损坏；错误不会输出部分行。查询不取得 index 锁，不检查坏 index/pending 或工作字节。相同 tip 复用图筛选结果；merged 组共用祖先集合。

`branch --list/-l` 及格式、排序、图筛选选项进入显式只读列表。默认列本地分支，`-r/--remotes` 列实际 fetched tracking，`-a/--all` 列两者，均排除 tags。pattern 对下述短名做完整的 `*`／`?` 通配匹配，多个 pattern 取并集：本地名称为 NAME，远端在 remotes-only 和 all 两种 scope 中都按 REMOTE/NAME 匹配。这与 for-each-ref 的完整引用前缀规则分开。大小写、排序、format、omit-empty 和 JSON 共用上述合同；`--show-current` 仅单独使用，返回当前分支名，detached 时为空，unborn 时保留真实符号名称。

显式列表只枚举已存引用，没有虚构的 detached/unborn 分支行。无参数 branch 与旧 `branch -vv` 显示保持原合同；未指定 format/JSON 的显式列表仍带原生完整 ID，远端行保持 `refs/remotes/...` 的旧拼写。创建、改名、复制、删除等写入不能与列表选项组合。Git 的全部展示 atom、日期/作者、颜色/列、version sort、stdin 模式、分页及其他选项仍未实现；不为没有存储的作者或时间生成占位数据。

回归见 [graph_queries_cli.rs](../tests/graph_queries_cli.rs) 的真实 Git DAG/名称/远端对照及固定图预期，以及 [query_cli.rs](../tests/query_cli.rs) 的完整文件保持、坏元数据、格式、对象和双架构数值边界检查。



## HTTP 与 SSH 远端广告

```sh
wasm-git ls-remote URL [OPTIONS] [PATTERN...]
wasm-git ls-remote DIR [REMOTE] [OPTIONS] [PATTERN...]
```

只支持既有 HTTP(S)/SSH URL；DIR 单独使用时选择 origin。若筛选默认 remote，明确写 `DIR origin PATTERN`，第二个位置不会猜成 pattern。支持 `--heads|--branches`、`--tags`（两者并集）、`--refs`、`--symref`、`--exit-code`、`--json` 和现有 `--allow-insecure-http`。`--` 结束选项识别。未知或重复选项明确失败。

默认输出 `ID TAB full-ref LF`，包含有实际 ID 的 HEAD、branches 和 tags；`--refs` 去掉 HEAD。模式使用 `*`/`?`，匹配完整引用或任意 slash 后的后缀。`--symref` 可输出 `ref: refs/heads/NAME TAB HEAD LF`；unborn 时该符号行也可存在，但不虚造 ID。`--exit-code` 在没有匹配的**实际 ID 行**时返回 2，因此可能输出一条 unborn 符号行同时退出 2。

查询只发一次空 payload 的 Advertise 请求，拒绝返回对象 payload、更新 tip、损坏 state 或协议 envelope。不执行 fetch，不建立仓库、不创建 remotes 目录或 tracking。配置模式仅读有界 regular config，不依赖坏 index/pending/本地 objects/tracking，也不取得写入或配置锁。复用现有 transport 的 URL、token、明文限制、超时与 framing 验证。JSON 单独标明 `advertised_only:true`、`objects_verified:false`、`unverified_objects:true`；远端提供的 ID 不等于已下载并验证的对象，不虚报 object kind/size。
