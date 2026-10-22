# HEAD、分支与共享路径选择

所有能力使用 uwgit 的原始 Wasm 对象、平面树和提交 DAG。Git 只出现在独立行为对照测试中。

## HEAD 的三种实际状态

```sh
wasm-git switch DIR --detach [REV]
wasm-git checkout DIR --detach [REV]
wasm-git checkout DIR TAG_OR_COMMIT
wasm-git switch DIR --orphan NEW_BRANCH
wasm-git switch DIR -
wasm-git worktree DIR add --detach NEW_DIR [REV]
```

普通 HEAD 文件仍保存分支名和一个 LF。分支尚无提交时即 unborn 状态。detached HEAD 直接保存完整小写提交 ID 和 LF；完整 ID 原本不能作为分支名，因此这个扩展没有名字歧义，也不需要临时分支。指针必须指向实际 commit，不能指向 blob/tree 或缺失对象。

detached 状态下 commit、amend、reset、merge/replay 只推进真实 HEAD 指针，原分支保持原 tip。分支列表明确显示 detached，status 的 `detached` 字段为 true；`symbolic-ref -q HEAD` 以空输出退出 1。不带明确目标 refspec 的 push 拒绝 detached 默认目标，显式 `HEAD:DESTINATION` 可按既有租约规则发布。

switch/checkout 仍先检查原 index/工作区是否干净，并预检 untracked 阻挡。已有 index 时同步完整受控树；没有 index 的旧仓库仍保留只切指针的行为。需要物化时使用 `restore DIR --source HEAD --staged --worktree`。普通文件导出的旧 checkout 语法保留。

orphan 创建尚无引用的新分支，并在干净工作区中清空 index、删除原 index 所拥有的工作文件，保留 untracked 文件。第一个提交没有父提交；旧分支和旧对象保留。已有目标分支、脏工作状态、其他工作树占用和 pending 操作均不允许借此覆盖。

linked worktree 可以同时 detached 在同一提交；这不占用任何分支。每次 detached 提交同步其注册指针，其他工作树继续使用各自 HEAD/index/工作字节。list 的 JSON 将 detached 的 `branch` 显示为 null；porcelain 使用独立 `detached` 行。

完整 bundle 为 detached HEAD 使用 manifest format 4，对象 envelope 和对象 ID 不变。新 clone/广告/fetch/unbundle 理解实际指针；旧客户端会拒绝扩展，不会把它误当成 unborn 分支。GC 与 fsck 将 detached HEAD 作为真实对象图根，故没有任何分支时也能保留并克隆这段历史。

HEAD 切换、提交和恢复使用各工作树自己的 `head-reflog.json`；上一检出身份使用各自的 `checkouts.json`。两者为有界、规范编码的本地恢复记录，各保留最近 4096 项，不进入 bundle。共享分支日志仍在原来的 reflog 中。写入故障会明确指出 HEAD 是否已经发布；prepared 冲突续作可补齐缺失的完成日志，重试不重复创建提交或完成事件。

HEAD 的批量 `symref-update/verify`、ref/oid 租约、显式 no-deref update 和 version 2 原子恢复见[引用事务](ref-transactions.md)。单独 symbolic-ref 同样使用该事务，保持原有指针操作语义及 index/工作字节。

## 修订与分支选项

```sh
wasm-git rev-parse DIR HEAD@{1}
wasm-git log DIR main@{upstream}~1
wasm-git cat-file DIR -t 'HEAD^{commit}'
wasm-git rev-list DIR 'HEAD^!'
wasm-git rev-list DIR 'MERGE^-2'
wasm-git branch DIR -r
wasm-git branch DIR -a
wasm-git branch DIR -f NAME [REV]
wasm-git branch DIR -M [OLD] NEW
wasm-git branch DIR -c [OLD] NEW
wasm-git branch DIR -C [OLD] NEW
```

`@` 是 HEAD；`REF@{N}` 选择该实际引用的第 N 个先前日志值，0 为最新。删除后重建的分支不继承先前同名分支的序号历史。显式 HEAD 使用当前工作树的 HEAD 日志；没有记录这一日志的旧仓库只保证 HEAD@{0}，不从其他工作树或普通祖先猜历史。空 ref 的 `@{N}` 使用当前分支日志，detached 时使用 HEAD 日志。

`@{-N}` 选择当前工作树第 N 次先前检出身份，并查询该分支现在的 tip，或实际保存的 detached ID。切换到已删除分支时明确失败。尚未记录本地 checkout 日志的旧历史不从共享 HEAD 日志猜测。

upstream 选择器在同一个验证快照中核对配置的 remote、URL、fetched tracking 身份和实际提交，可接 `~N/^N` 与 `^{commit}`，也可用于 log、对象路径、merge-base、restore 等命令。缺配置、缺 fetched tip、身份不匹配均失败，不发起隐式 fetch。

`^{}`、`^{commit}`、`^{object}` 对 commit 修订进行类型确认；`REV:PATH` 继续查询真实命名树。`REV^@` 展开所有父提交，`REV^!` 只包含 REV 并排除父历史；`REV^-N` 排除第 N **父**及其祖先，N 不是代数。旧历史没有墙上时钟时间，日期 selector 不从文件 mtime 或提交顺序伪造。

branch 的 -f 仍拒绝当前和其他工作树占用的分支。-M 可替换非占用的已有目标；-c/-C 复制源 tip 和 upstream 关联，-C 替换目标时会清除目标旧关联，不能使无关联的源继承旧目标配置。-d 优先检查已验证的 upstream tip，没有可用 upstream 时检查 HEAD。多文件 I/O 失败会报告已发布范围，不承诺断电时跨引用/日志/config 的事务回滚。

## 统一路径选择

```sh
wasm-git add DIR -A
wasm-git add DIR -u -- modules/
wasm-git add DIR -n -- '*.wasm' ':!generated/'
wasm-git restore DIR --source HEAD -- ':(glob)modules/**/*.wasm'
wasm-git reset DIR HEAD -- ':(icase)MODULES/*.WASM'
wasm-git ls-tree DIR HEAD --name-only -- ':(literal)module[1].wasm'
wasm-git archive DIR HEAD -o NEW_TAR -- '*.wasm' ':(exclude)private/'
```

restore、按路径 reset、checkout 的显式路径模式、archive、ls-tree、底层 diff、clean 和 mergetool 共享相同解析器。选择在命令已准入的真实候选集合上计算，不用 pattern 遍历或绕过文件系统保护。精确路径、目录前缀、单个前导 `./`、`.`/`./` 保留；内部空组件、`.`、`..` 和 `.uwgit` 路径拒绝。

普通 `*`、`?`、字符组可以跨 `/` 匹配。`:(glob)` 中普通通配符不跨 `/`，完整组件 `**` 表示递归目录。`:(literal)` 按原字符匹配；`:(icase)` 忽略大小写；`:(top)` 使用本来就以 DIR 为根的路径。支持 `:(exclude)`、`:!`、`:^`，先取正选择器并集，再统一排除；只有排除项时从全部候选中排除。花括号作为普通字符，不做 shell 展开。单独 `:` 表示无路径限制。

每个正选择器必须在排除前匹配，排除项可以不匹配；全部排除可以得到空结果。未匹配、非法 magic 或无效 glob 在任何发布前失败。不支持的 attr magic 明确报错，不静默当成普通字符串。

add 的 -A/--all 纳入受控删除及新 Wasm 文件，-u/--update 只更新已有受控路径；-n/--dry-run 不改 index，-f/--force 可明确加入忽略的 Wasm 文件。目录选择跳过普通文本，仍验证所选 Wasm 文件头；.gitignore/.uwgitignore、嵌套仓库、符号链接和特殊文件保护继续生效。通配符和目录不能替未命名 legacy 提交猜文件名，首次建立映射仍需明确实际路径。

这些基础能力不表示全部 Git 选项已经齐备；索引冲突 stages、交互 patch、日期元数据等剩余差异仍见[能力矩阵](git-command-coverage.md)。
