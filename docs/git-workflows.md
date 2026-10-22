# 多 Wasm 文件树与 Git 类工作流

一个 format 2 提交保存路径到完整 Core Wasm 原字节对象的映射，以及父提交、消息和 tree ID。
文件名、新增、删除、移动、空树都进入历史。模块字节不经 WAT 往返，也不按语言特性配置拒绝未知指令或未知 section。
暂存只要求 Core Wasm 的八字节头；验证与审计结果另外报告。

本项目提供自己的对象格式和网络协议。HTTP(S) 与 SSH 的部署、认证、配额及退出码见 [server](server.md)；
它不与原生 Git wire、Git tree/pack 格式互操作。提交树只保存 Wasm 文件，不保存任意源码、权限模式或符号链接。

## 建立和编辑文件树

```sh
wasm-git init ./history
cp /path/a.wasm ./history/a.wasm
cp /path/b.wasm ./history/b.wasm
wasm-git add ./history a.wasm b.wasm
wasm-git status ./history
wasm-git commit ./history -m 'two modules'
wasm-git switch ./history -c topic
# 编辑 ./history/a.wasm
wasm-git add ./history a.wasm
wasm-git mv ./history b.wasm renamed.wasm
wasm-git commit ./history -m 'edit one module and record a rename'
```

add 的路径相对于 DIR；后续 add 累加或更新指定路径，不移除其他 tracked 文件。
路径为 UTF-8 普通相对路径，可含目录；拒绝绝对路径、空组件、点、父引用、反斜杠、冒号、控制字符与任何大小写的 .uwgit。
树不能同时含普通文件 a 和 a/b.wasm。工作区不跟随符号链接。

add、rm、mv、restore 支持 `--` 路径分隔符；它后面的参数全部按字面路径处理。
例如 `add DIR -- --help` 可以暂存名为 `--help` 的模块，`mv DIR -- --help new.wasm` 可以移动它，
`restore DIR -- --source` 从 index 恢复名为 `--source` 的路径，`rm DIR -- --cached` 实际删除名为 `--cached` 的文件。
选项须放在分隔符前：`rm DIR --cached -- --help` 才表示保留工作文件、只删除该字面路径的 index 条目。
分隔符前独立的 `--help` / `-h` 仍无 I/O 返回帮助；分隔符后的同名路径不触发帮助。

| 命令 | 行为 |
|---|---|
| `init DIR` | 创建仓库，拒绝覆盖已有 .uwgit。 |
| `add DIR FILE...` | 一次预读并检查全部路径，然后发布完整 index；任一参数失败不暂存前面的文件。文件的全部原字节进入 index。 |
| `status DIR` | JSON format 2，files 按路径列出 staged added/deleted/modified/clean 与工作文件 clean/modified/deleted/untracked；同时列出未跟踪的普通 Core Wasm 文件。 |
| `ls-files DIR` | 列出已建立 index 的路径和实际 stages；支持工作区筛选、格式及忽略规则，见[索引合同](index-stages.md)。没有本地 index 时为空。 |
| `commit DIR -m MESSAGE` | 提交整个 index，创建 format 2 tree commit；没有变化时报错。 |
| `commit DIR --allow-empty -m MESSAGE` | 允许不变的树；新仓库也能显式提交真正的空树。 |
| `commit DIR --amend [-m MESSAGE]` | 用当前 index 替换最新提交，保留其父列表；缺少消息时保留原消息。没有 index 时从已命名 HEAD 树读取。 |
| `mv DIR OLD NEW` | 保留 staged 和工作文件各自的原字节，移动文件并更新 index 路径；下一次提交记录路径变化。拒绝覆盖目标。 |
| `rm DIR FILE...` | 删除明确指定的 tracked 普通文件与 index 条目；脏内容默认拒绝。 |
| `rm DIR --cached FILE...` | 只删 index 条目，保留工作文件；独有 staged 字节不能无提示丢弃。 |
| `rm DIR -f FILE...`、`rm DIR --cached --force FILE...` | 明确允许丢弃相应 tracked 或 index 改动。只处理指定条目，不扫描删除其他文件。 |

rm 省略 FILE 仅在 index 恰好含一个文件时接受，保留旧单文件命令用法。
删除最后一个条目后仍保存空 index，普通 commit 会记录实际空 tree，能通过历史恢复全部文件。
status 的未跟踪扫描排除 .uwgit，不跟随目录或文件符号链接，只读取候选普通文件的八字节头；
它不自动 add，不把非 Wasm 文件伪装成已跟踪内容。

clone 复制对象、引用和 HEAD，不猜测工作目录布局，也不自动建立 index。
首次 add 到没有 index 的 format 2 仓库会先保留 HEAD 中其他路径，避免只 add 一个文件就默默删除其他模块。
需要完整物化 clone 时使用：

```sh
wasm-git restore ./peer --source HEAD --staged --worktree
```

## 恢复、reset 和分支切换

| 命令 | 行为 |
|---|---|
| `restore DIR [FILE...]` | 从 index 恢复工作文件；省略路径时恢复整个 index，保留其他未选中的脏文件。 |
| `restore DIR --source REV [FILE...]` | 从提交树恢复相应工作文件，index 不变；整树恢复也处理该树中的新增和删除。 |
| `restore DIR --staged [FILE...]` | 从 HEAD 恢复 index，工作文件不变。 |
| `restore DIR --source REV --staged --worktree [FILE...]` | 同时恢复 index 与工作文件；可安全建立 clone 的工作区。 |
| `restore DIR --source REV --overlay [--staged] [--worktree] [PATH...]` | 只恢复源树存在的选中路径，保留源树没有的无关路径；所选路径的受控文件／目录冲突按替换处理。 |
| `restore DIR [--source REV] --file PATH --output NEW_FILE` | 独占导出指定模块，不修改 index 或工作文件；单文件树可省略 file。 |
| `restore DIR REV --output NEW_FILE` | 保留旧导出用法；多文件树需要明确路径。 |
| `reset DIR [--mixed] [REV]` | 移动 HEAD 并替换完整 index，保留工作文件。 |
| `reset DIR --soft [REV]` | 只移动 HEAD。 |
| `reset DIR --hard [REV]` | 移动 HEAD，替换完整 index 与已跟踪工作文件，处理树内新增、删除；拒绝覆盖或删除挡路的 untracked 文件。 |
| `reset DIR [REV] -- PATH...` | 从 REV（默认 HEAD）恢复所选 index 条目，保留 HEAD、工作文件和其他暂存内容；不能组合 soft/mixed/hard。 |
| `switch DIR NAME` | 切换分支，已有 index 时同步完整文件树；要求 staged 与工作区无改动。 |
| `switch DIR -c NAME [REV]` | 创建并切换分支；新仓库可重命名 unborn HEAD。 |
| `switch DIR --detach [REV]` | 真实 HEAD 指向提交 ID，后续提交不移动原分支；已有 index 时同步完整树。 |
| `switch DIR --orphan NAME` | 新 unborn 分支，清空干净的受控树与 index，保留 untracked；首个提交没有父提交。 |
| `switch DIR -` | 返回当前工作树上一检出身份，可为分支或 detached ID。 |
| `checkout DIR NAME`、`checkout DIR -b NAME [REV]` | 分别复用 switch 与 switch -c 的分支切换和保护。 |
| `checkout DIR -- PATH...` | 从 index 恢复选中工作路径，index 和 HEAD 不变。 |
| `checkout DIR REV -- PATH...` | 从 REV 按 overlay 规则恢复选中 index 与工作路径，HEAD 不变。 |

restore、checkout 路径模式及 reset 路径模式支持精确文件、目录前缀和 `.`／`./`，并允许单次开头的 `./`。
末尾单个 `/` 表示目录，只匹配后代，不匹配同名普通文件。中间空组件、`.`、`..` 与元数据路径仍被拒绝。
现已共享 glob/literal/icase/top/exclude 路径选择，具体规则与 HEAD/分支扩展见 [HEAD 与路径选择](head-and-pathspec.md)。
每个显式选择器都必须匹配候选路径，任一未匹配时全部拒绝，不再无操作报告成功。显式 `--` 后必须有路径；restore 不带路径仍保持整树恢复用法。
普通 restore 和 reset 路径模式从 index／source 并集选择，支持源树中的删除；overlay 从 source 选择，精确路径不在 source 时拒绝。
overlay 只额外移除与所选源路径有文件／目录前缀冲突的受控条目，其他源树缺席条目保持不变；untracked 阻挡项仍会使全部操作在写入前失败。
指定路径的 reset 在首个提交前明确拒绝，可用 `rm DIR --cached -- PATH...` 取消暂存。

```sh
wasm-git checkout ./history -b topic HEAD
wasm-git checkout ./history -- modules/
wasm-git checkout ./history HEAD~1 -- modules/a.wasm
wasm-git reset ./history -- modules/a.wasm
```

旧 `checkout DIR REV NEW_FILE [--file PATH]` 仍是独占导出语法；从修订还原已有路径必须明确写 `REV -- PATH`。
若旧导出的目标本身名为 `--`，使用 `./--` 或绝对路径，避免与路径分隔符混淆。
分隔符后的 `--file`、`--help` 等都是字面路径，不触发导出或帮助。没有 index 的对象仓库仍不因分支切换自动建立工作区；detached HEAD 已支持，根据文件是否存在猜测 checkout 模式仍不支持。

reset 缺省 REV 为 HEAD。clone 没有 index 时的普通历史操作保持对象仓库模式，不自动创建工作文件；
显式 restore --staged --worktree 或 reset --hard 可建立工作区。
全部目标路径先检查，再写第一个文件；后面的 untracked 冲突不能导致前面的模块先被覆盖。
新普通目录可按需要创建；已存在的非目录父路径、目录目标、符号链接均报错。
不以递归删除目录来解决文件/目录冲突。输出文件永不覆盖已有文件、目录、符号链接或元数据。

所有用户文件导出共用同一边界，包括 show/checkout、restore、stash、cat-file、bundle，以及 patch/apply 的文件和仓库模式。
输出父目录必须已存在；解析父目录别名后，任意大小写的 `.uwgit` 路径组件都会阻止导出，
因此不能借助父目录符号链接写入元数据。普通父目录别名允许使用，发布使用已经解析的目录。
末尾为分隔符、`.` 或 `..` 的请求不是新文件名；`missing/` 或 `missing/.` 不会被改写成普通文件 `missing`。

## 旧 format 1 历史迁移

format 1 是一个没有文件名的原始 Wasm 提交。其对象 ID、commit payload、旧 bundle 与原字节继续可读，
不会为旧历史捏造 module.wasm 等名称。无 anchor 的旧 clone 保持无 index；status 明确报告 legacy_head_unmapped。

旧二进制 UWGITIDX 版本 1 index 自带原 path，可作为显式 anchor 读取。
没有旧 index 时，用户第一次 add DIR PATH 的首个路径确定 legacy_path；PATH 可以包含新的模块字节。
该映射及其他已暂存路径由下一次 format 2 提交持久保存，后代继承，空树也保留 anchor。
旧内容没有变动也能提交这次明确命名的 format 1 到 format 2 升级。

```sh
# 在旧仓库中由用户明确选择历史中未命名模块的新路径
wasm-git add ./legacy chosen.wasm
wasm-git add ./legacy second.wasm
wasm-git commit ./legacy -m 'name legacy module and add second module'
```

兼容 `commit DIR WASM -m MESSAGE` 的旧显式文件提交；当 HEAD 已是 tree 时拒绝该形式，防止它丢弃其他文件。
旧 `checkout DIR REV NEW_FILE` 仍独占导出 format 1 原字节；tree 提交导出需指定路径，参见命令帮助。
旧 format 1 的单独导出不创建任何 filename mapping。

## stash 与历史重放

| 命令 | 行为 |
|---|---|
| `stash DIR [push [-m MESSAGE]]` | 持久保存 base、完整 index 与各 tracked 工作文件原字节/缺席状态，再恢复 HEAD 的 index 与工作树；首个提交前拒绝。 |
| `stash DIR list` | 按新到旧列出固定数字 ID、消息、路径及两类字节数；drop 不重编号。 |
| `stash DIR apply ID` | 以保存的 base 分别三方合并 index 和工作树，恢复新增、删除和修改；要求当前 index/worktree 干净。 |
| `stash DIR pop ID` | apply 完全成功后才删除保存条目；冲突保留 stash。 |
| `stash DIR apply ID --output NEW_FILE` | 仅当快照恰有一个现存工作文件时导出其原始字节，不改工作区和 index。 |
| `stash DIR drop ID` | 明确删除本地快照。 |
| `merge-base DIR LEFT RIGHT` | 返回全部最佳共同祖先。 |
| `merge DIR REV -m MESSAGE` | 保守三方合并；独立文件和受支持的文件内修改可合并，冲突不发布部分结果。 |
| `merge DIR REV --ff-only [-m MESSAGE]` | 只允许快进或目标已被包含的无操作，分叉时明确拒绝，不创建合并提交。 |
| `merge DIR TARGET_ID -m MESSAGE --resolved WASM --expect-head HEAD_ID` | 旧单模块显式解决接口，受其格式限制；不能用一个文件隐式覆盖多文件树。详见 [merge](merge.md)。 |
| `merge DIR TARGET_ID -m MESSAGE --resolved-index --expect-head HEAD_ID [--expect-branch NAME]` | 以真实 index 的完整树作为明确解决结果，保存双父历史与两侧逐文件审计；不修改 index 或工作文件，允许未暂存修改；没有 index 不代表空树。 |
| `cherry-pick DIR REV [-m MESSAGE] [--mainline N]` | 重放选定提交相对父提交的修改，保留全部文件路径，创建新提交。 |
| `revert DIR REV [-m MESSAGE] [--mainline N]` | 反向重放，创建新提交，保留原历史。 |
| `cherry-pick/revert DIR TARGET_ID --resolved-index --expect-head HEAD_ID [--expect-branch NAME] [--mainline N] [-m MESSAGE]` | 用户审定完整 index 后发布单父提交，父为审定的 HEAD；保留 index 与未暂存工作字节，报告手工身份及各侧审计。 |
| `rebase DIR UPSTREAM [--onto NEW_BASE]` | 只重放线性单父链，要求唯一 merge base；全部重放先在内存完成，晚冲突也不发布中间提交。 |

stash 可以保存编辑中的非 Wasm 工作字节或已删除文件。base 未变时原样回放；需要合并但无法解释或冲突时明确拒绝。
全部文件的合并与安全检查在第一处写入前完成。stash 属于本地元数据，不随 clone/bundle/fetch/push 传输；
旧单文件 format 1 stash 可读取，后续写入升级为完整树格式。

merge、pull、cherry-pick、revert、rebase 的冲突输出 JSON 并返回 2；其他命令错误返回 1。
默认 rebase 冲突不建立半完成状态；可用下述显式录制模式保存队列。不支持交互式或保留 merge 拓扑。
自动合并与重放要求已建立的工作区干净，成功后同步全部 tracked 文件和 index。
显式 `--resolved-index` 操作只提交用户审定的完整暂存树，允许未暂存修改，不自动补入其他非冲突变更。
cherry-pick／revert 的此模式只产生一个父提交；目标及选定 mainline 绑定在报告中，不成为第二父提交。
它不要求此前冲突，也不建立 pending 状态。详细契约见[快进约束与单父手工重放](replay-resolution.md)。

### 显式录制单目标冲突

```sh
wasm-git merge ./history topic --record-conflict -m 'integrate topic'
# 若返回冲突，查看报告和 status，准备整个解决结果，再显式暂存
wasm-git add ./history modules/a.wasm
wasm-git merge ./history --continue --resolved-index
# 放弃并恢复原 index 和原受控工作文件
wasm-git merge ./history --abort
# 或只忘记操作，保留当前解决中的内容
wasm-git merge ./history --quit
```

continue、abort、quit 是三种互斥的选择，不应顺序执行。cherry-pick/revert 支持相同入口；单目标 `--skip` 恢复原状态并结束本次操作，merge 没有 skip。
`--record-conflict` 仅在实际冲突时保存 `.uwgit/pending.json`，不把半成品写入 index 或工作文件；成功、快进或已包含目标时不留状态。
默认命令仍只报告冲突。录制前要求受控 index/worktree 干净；没有 index 的命名对象仓库也可以录制，但无明确路径的旧未命名历史须先建立 index。

`--continue --resolved-index` 表示用户明确审定了**整个**暂存树，包括所有新增、删除和不相关路径；程序没有 Git 的 unmerged stages，不能自动确认每个冲突已经解决。
续作使用保存的操作、原 HEAD、目标和 mainline，不能同时指定新的 REV、消息或 mainline。
merge 发布双父提交，pick/revert 发布单父提交；index 和工作文件均不改变，允许保留未暂存修改。
已有 pending 时，普通 commit/amend、新历史操作、整树 reset、分支切换、绑定分支重命名和 stash push/apply/pop 会拒绝；add/rm/mv/restore/路径 reset 仍用于准备结果。

abort 恢复原 index 的原编码与原受控工作文件，只处理开始时已有的受控路径。
后来新增的工作文件保留为 untracked；它们或 symlink/目录阻挡原路径恢复时，在写入前拒绝并保留状态。
原本没有 index 时，abort 恢复其不存在状态，工作文件全部保留。quit 只清记录，可用于外部写入后已陈旧的操作，不替用户回退其他人的提交。

续作在移动引用前先安装完整对象闭包，并持久化 prepared 提交 ID 和所用 index 原始摘要。
若中断发生在引用已发布、状态未清理之间，重试识别实际提交、补缺本次唯一 reflog 并清理，保留后来移除或损坏的 index，不重复提交。
引用未发布时，重试必须仍是同一分支、原 HEAD 和同一份 index；第三种 HEAD 不会被自动重置。
这是受检查的恢复流程，不承诺多个工作文件在断电时整体回滚；I/O 失败报告已完成范围并保留可重试的状态。
pending 是本地元数据，不进入提交、bundle、clone 或传输；其规范 JSON 总大小限制为 64 MiB，包含原 index 备份。
详细验证见[单目标续作](pending.md)。

### 显式录制线性 rebase

```sh
wasm-git rebase DIR UPSTREAM --onto NEW_BASE --record-conflict
# 审阅当前 stopped_at 步骤及其 base/ours/theirs，准备整个暂存结果
wasm-git add DIR -- reviewed.wasm
wasm-git rebase DIR --continue --resolved-index
# 也可跳过当前原提交，随后继续重放余下步骤
wasm-git rebase DIR --skip
# 或恢复最初 index/受控工作文件，或只忘记本地状态
wasm-git rebase DIR --abort
wasm-git rebase DIR --quit
```

`--record-conflict` 冻结完整 upstream/onto ID、唯一 merge base 与原线性单父队列。
所有步骤成功后才一次移动原分支；中间成功步骤仅作为本地对象和 journal 进度保存，status 显示当前位置。
每次 continue 的完整 index 只替换当前冲突步骤；随后步骤自动重放，可能再次返回冲突和退出 2。
当前步骤的 ours 是已重放的进度树，不能用仍指向最初 tip 的 HEAD 代替。
手工树不会自动补入当前步骤的其他非冲突路径，须审阅完整报告后显式暂存整个结果。

continue/skip 保留当前 index 和全部工作文件，即使最终提交还包含后续自动步骤；要物化最终树可在保存本地编辑后显式 restore。
skip 跳过当前原提交并继续余下队列，不使用当前 index 内容，也不恢复最初 index；abort 才恢复最初 baseline。
quit 只移除操作记录，不发布中间进度。pending 不随 clone、bundle、HTTP 或 SSH 传输。
发布前保存 prepared 最终 tip；中断后重试按原 generation 修复 reflog/清理。自动 begin/skip 准备结果无需当前 index；continue 准备结果在发布前要求同一份有效 index。
旧单目标 version 1 journal 的编码继续可读。验证及精确限制见[rebase 续作](rebase-pending.md)。

## 引用、查询和本地配置

| 命令 | 行为 |
|---|---|
| `branch DIR [NAME [REV]]` | 列出或创建分支。 |
| `branch DIR -d NAME`、`branch DIR -D NAME` | 删除已合并分支，或明确强制删除；不能删当前分支。 |
| `branch DIR -m NEW`、`branch DIR -m OLD NEW` | 重命名分支与必要的 HEAD。 |
| `branch DIR -u REMOTE/BRANCH [LOCAL]`、`--set-upstream-to[=]REMOTE/BRANCH` | 为已提交本地分支设置已 fetch 的远端分支关联；省略 LOCAL 使用当前分支。 |
| `branch DIR --unset-upstream [LOCAL]`、`branch DIR -vv` | 取消关联，或以稳定 JSON 列出本地分支及 upstream 的实际 fetched tip / gone 状态。 |
| `tag DIR [NAME [REV]]`、`tag DIR -d NAME` | 列出、创建、删除轻量标签。 |
| `log DIR [REV]`、`show DIR REV` | 提交 DAG 或提交 JSON，tree commit 含 tree ID，旧 commit 含 wasm ID。 |
| `rev-parse DIR REV`、`reflog DIR` | 解析完整提交 ID，或显示本地引用更新顺序与旧/新值。 |
| `cat-file DIR -t OBJECT`、`cat-file DIR -s OBJECT` | 对象类型与 payload 长度。 |
| `cat-file DIR -p OBJECT` | 提交/tree 规范 JSON；二进制 Wasm 使用 output。 |
| `cat-file DIR OBJECT --output NEW_FILE` | 独占导出原始 payload。tree payload 的 entries 将路径映射到 blob ID。 |
| `ls-tree DIR REV [--name-only\|--object-only] [-z] [-- PATH...]` | 默认 JSON 显示实际平面树、blob ID 与 payload/envelope 大小；每个选择器必须匹配，尾斜线只匹配目录后代。旧 unnamed 提交仅 JSON 保留 legacy witness。 |
| `show-ref DIR [--head] [--heads] [--tags] [--verify] [--quiet\|--hash\|--json] [PATTERN...]` | 列出本地、标签与 fetched tracking 引用；普通字面后缀筛选、精确引用验证与无匹配退出 1。 |
| `for-each-ref DIR [--json\|--format STR] [--sort KEY]... [--count N] [PATTERN...]` | 完整引用 prefix 或 `*`/`?` 筛选，有限 format atoms，按实际 ID/名称/payload size 排序；无匹配退出 0。 |
| `count-objects DIR [-v] [-H]` | 按唯一真实对象统计逻辑 payload/envelope 字节与明示 roots 的可达性，不虚报分配空间或 Git packs。 |
| `describe DIR [REV] [--exact-match] [--always] [--long] [--first-parent] [--abbrev N] [--json]` | 根据轻量标签祖先闭包生成可读名称；支持 match/exclude 列表及重置，缩写在全部对象中唯一。 |
| `archive DIR REV --output NEW_TAR [--prefix PREFIX/] [--legacy-path NAME] [-- PATH...]` | 独占导出选定已提交原字节的 ustar，stdout 为 provenance/SHA 报告；旧单模块必须显式命名。 |
| `bisect DIR start [--no-checkout] [--first-parent] BAD GOOD...` | 开始仅本地的历史二分，冻结端点完整 ID；不切换 HEAD/index/worktree。 |
| `bisect DIR good|bad|skip [REV...]` | 保存用户测试判断并选择下一候选；bad 最多一个修订，无 REV 时使用候选而非 HEAD。 |
| `bisect DIR status|next|log|reset` | 查询候选或完整判断，reset 仅清会话；跳过歧义明确报告，不猜唯一首个 bad。 |
| `ls-remote URL [OPTIONS] [PATTERN...]`、`ls-remote DIR [REMOTE] [OPTIONS] [PATTERN...]` | HTTP(S)/SSH Advertise-only，无本地写入或对象下载；JSON 明示对象尚未验证，`--exit-code` 没有实际 ID 匹配时退出 2。 |
| `diff DIR [--cached] --format json` | 全路径 tree_diff；文件内仍含原完整审计，新增/删除明确使用 None 及单侧完整原字节见证，不用空模块冒充不存在。 |
| `fsck DIR` | 验证全部对象、tree 路径、引用和闭包，包括不可达对象。 |
| `config DIR [KEY [VALUE]]`、`config DIR --unset KEY` | 只读写本地数据，不执行 shell。 |

revision 支持完整 ID、至少四位唯一提交前缀、HEAD、分支、标签及 ~N/^N 组合。
refs/heads/NAME、refs/tags/NAME 可消歧；fetch 后支持 origin/main 和 refs/remotes/origin/main。
本地分支与标签是受限 ASCII 名称，支持 `feature/x` 等正常层级；空组件、`.`、`..`、`.lock` 组件及 `refs/` 前缀不能作为分支名。多工作树占用保护与新底层入口见[原生命令手册](native-commands.md)。
名称为 1–128 字节，首字符为字母或数字；HEAD、完整对象 ID 和 `.lock` 后缀属于保留名称。

五个只读入口的输出、过滤、格式、统计 roots 和不兼容选项详见[查询契约与验证](queries.md)。本地对象查询使用一个已验证快照；损坏的 index/pending 或工作文件不参与已提交对象的读取。
describe 名称解析、标签选择、归档固定元数据与 legacy 命名规则见[描述与归档](describe-archive.md)。归档保留未知 Wasm 字节，不依赖工作文件或重新编码；输出必须是新文件。
历史二分的祖先集合算法、用户判断假设、持久会话及未支持选项见[bisect 契约](bisect.md)。可将报告的候选完整 ID 交给 show、inspect 或 archive，自行测试后再标记。

`rev-parse DIR '@{upstream}'`（简写 `@{u}`）及 `NAME@{upstream}` / `NAME@{u}` 查询该本地分支的实际 fetched 远端 tip。
尚未 fetch、远端分支已消失时明确失败；不退回本地 HEAD，也不接续 ancestry 或 reflog 表达式。
从 `origin/main` 创建普通 branch/switch 不自动设置关联；可随后显式 `branch DIR -u origin/main topic`。

upstream 独立保存在本地 `.uwgit/upstreams.json`，只关联已提交的本地分支；不会进入提交、bundle 或远端传输。
网络 clone 为有提交的初始 HEAD 设置 origin 同名关联；本地 clone 不复制源仓库的关联。
分支重命名移动关联，删除分支先清关联；remote rename 移动关联，remote remove 清除对应关联。
多个文件的 I/O 失败会报告已完成与不确定的步骤；不承诺跨文件事务回滚。损坏的本地关联配置会明确拒绝操作。

```sh
wasm-git branch ./peer -u origin/main topic
wasm-git switch ./peer topic
wasm-git branch ./peer -vv
wasm-git rev-parse ./peer '@{u}'
wasm-git pull ./peer --ff-only
# topic 跟踪 main 时，默认 simple push 要求显式指定异名目标
wasm-git push ./peer origin topic:main --set-upstream
```

默认 pull 使用当前分支关联的 remote/branch；没有关联时沿用 origin/本地同名分支。
仅显式指定相同 remote 时仍采用关联分支，显式其他 remote 时采用本地同名分支，明确给出 BRANCH 时以它为准。
默认 push 使用关联 remote（否则 origin），隐式目标为本地同名分支；若该 remote 正是 upstream remote 而两端分支异名，则拒绝并要求显式 refspec。
`-u` / `--set-upstream` 不放宽此保护；它只在单个本地分支的远端更新被精确确认后保存关联，不支持 tags/delete 或任意提交 ID 来源。
保存前再次检查 remote 身份、本地分支 tip 和旧关联；远端成功、本地保存失败时明确报告远端已发布，不能当作未发送重试。
push 不用广告值伪造 fetched tracking；新目标在 fetch 前可显示 gone。没有 push.default/pushRemote 等策略配置。

配置 key 须含点且组件非空，只用 ASCII 字母、数字、点、下划线或连字符，最多 128 字节；
value 最多 4096 字节且无控制字符。没有 hook/filter 或配置命令执行。

## 离线与 HTTP/SSH 交换

| 命令 | 行为 |
|---|---|
| `clone SOURCE_DIR NEW_DIR`、`clone URL NEW_DIR` | 完整验证后复制对象、文件树、分支、标签与 HEAD，目标必须不存在。网络 clone 配置 origin。 |
| `bundle DIR NEW_BUNDLE_FILE`、`unbundle DIR BUNDLE BRANCH` | 离线交换整个已验证对象闭包；导入已有分支要求快进。已有本地 index 时不能直接导入当前分支，应导入 incoming 后 merge。 |
| `remote DIR [-v]`、`remote DIR show NAME` | 列出 remote 或配置/最近广告。 |
| `remote DIR add NAME URL`、`remote DIR remove NAME`、`remote DIR rename OLD NEW` | 管理本地 remote。 |
| `fetch DIR [REMOTE]` | 缺省 origin；安装对象及 tracking refs，不改变本地分支、index 和文件。 |
| `pull DIR [REMOTE] [BRANCH] -m MESSAGE` | fetch 后合并远端完整树；缺省选择与当前本地分支同名的远端分支，缺失时要求显式指定 BRANCH，冲突不发布部分树。 |
| `pull DIR [REMOTE] [BRANCH] --ff-only [-m MESSAGE]` | fetch 后只允许快进或祖先无操作；拒绝分叉时保留本地 HEAD、index 和工作文件，fetch 导入的对象与 tracking 可以保留。 |
| `push DIR [REMOTE] [SOURCE:DESTINATION]` | 正常快进推送，始终校验远端广告旧值。 |
| `push DIR [REMOTE] [SOURCE:DESTINATION] --force-with-lease OLD_ID` | 仅在明确旧值仍匹配时请求强制更新；absent 要求不存在，服务端也须允许 force。 |
| `push DIR [REMOTE] --tags` | 顺序推送标签，明确 atomic:false。 |
| `push DIR [REMOTE] --delete BRANCH_OR_QUALIFIED_TAG [--force-with-lease OLD_ID]` | CAS 删除远端引用，不能删除服务端当前 HEAD 分支。 |

URL 是 http(s)://HOST/REPO 或 ssh://USER@HOST/ABSOLUTE/ROOT/REPO，可带端口。
HTTP bearer token 来自 UWGIT_REMOTE_TOKEN，不写入配置；非 loopback 明文 HTTP 要显式 --allow-insecure-http。
SSH 使用系统认证、主机密钥校验与远端 server --stdio。详细部署见 [server](server.md)。

消息选项后的 `--help`、`-h` 或 `--allow-insecure-http` 均是字面消息，不触发帮助或开启传输选项。
config 的 VALUE 同样按字面值保存。独立的 `--help`/`-h` 仍在仓库访问和网络请求前返回帮助。
restore、stash apply、cat-file 的 `--output` 值也可为字面 `--help` / `-h`；它后的独立帮助选项仍触发帮助。
单值选项的操作数若是 `--`，先将其作为值消费；只有真正的分隔符才终止选项预扫描。

## 持久化与边界

新 index 使用九字节 UWGITIDX\\x02 头，加规范 JSON：
`{format:2,files:{path:[完整原字节]},legacy_path:null或显式路径}` 及换行。
版本 1 的长度前缀二进制 index 仍可严格读取，发布新 index 时升级。
配置和 stash 同样严格校验 canonical JSON、重复/未知字段、路径、Core 头和长度，不静默修复损坏元数据。

工作区命令共享 index.lock；对象与引用使用 write.lock，历史写入同时 CAS 审定的分支名和旧 ID。
所有文件的逻辑冲突先预检；新文件独占创建，已跟踪文件通过同目录完整临时文件替换。
文件与目录可以相互转换，包括多层路径：先核对所有阻挡项，再移除应删除的受控文件，
清理由受控文件形成的空目录，最后建立目标父目录并写入模块。
将目录替换成文件时会检查整个子树；非 Wasm 的未追踪文件、无受控后代的空子目录、
符号链接和特殊文件同样会阻止操作。保留的同级内容不会被递归删除。
mv 分别保留原暂存字节与未暂存工作字节，目录转换不会自动把未暂存修改纳入提交。
引用、多个文件与 index 不是跨文件断电事务；引用已发布而后续 I/O 失败会明确报告完成范围。
锁不隔离有目录写权限者绕过程序的任意外部删除、目录替换或修改。

明确的纯 Wasm 边界是：提交树保存 Core Wasm 原字节模块及路径，不存储任意源码树、执行位或符号链接；
对象、bundle 和 HTTP/SSH RPC 使用本项目格式，不提供原生 Git wire/tree/pack 互操作。
这些范围与未知指令、未知 section 的原字节保留规则相互独立。

当前未实现的 Git 功能另有 detached/orphan HEAD、多目标 pick/revert 队列、
unmerged index stages、交互 rebase、annotated tag、提交签名与自动 GC 等；这些是功能缺口，需要分别补充接口和状态契约。
默认冲突不建立操作记录，abort/continue 只用于已显式录制的操作。checkout 已提供显式分支与路径入口，并保留独占导出用法。
完整已支持/部分支持/缺失矩阵、当前安全用法及实施优先级见 [Git 命令覆盖与当前缺口](git-command-coverage.md)。
SHA-256 表示内容完整性，不证明作者身份或行为。审计范围见 [README](../README.md)、[patch](patch.md)、[trace](trace.md)。

索引未解决 stages、`restore/checkout --ours/--theirs`、`read-tree -m`、`update-index`、`checkout-index` 和底层列表合同见[原生索引](index-stages.md)。未解决项不能用作完整提交树。
