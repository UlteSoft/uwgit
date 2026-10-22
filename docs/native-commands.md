# 原生 Wasm 仓库命令

这些命令直接使用 uwgit 的原始 Wasm 对象、文件树、提交 DAG 和传输协议。产品进程不通过 Git 执行版本操作。Git 仅用于独立行为对照测试。

## 对象与引用

```sh
wasm-git hash-object DIR -w module.wasm
wasm-git hash-object DIR --stdin < module.wasm
printf '100644 wasm OBJECT_ID\tmodules/a.wasm\n' | wasm-git mktree DIR
wasm-git write-tree DIR
wasm-git read-tree DIR TREE_OR_COMMIT
wasm-git read-tree DIR --empty
wasm-git commit-tree DIR TREE_ID -p PARENT_ID -m 'reviewed snapshot'
wasm-git update-ref DIR refs/heads/topic NEW_ID EXPECTED_OLD_ID
wasm-git update-ref DIR -d refs/heads/topic EXPECTED_OLD_ID
wasm-git rev-list DIR --parents --first-parent HEAD
wasm-git rev-list DIR --count OLD..NEW
```

`hash-object` 的 `wasm` 和 `blob` 都要求 Core Wasm 版本一文件头。`tree`、`commit` 使用原生规范编码的 JSON payload；写入前核对完整对象图，缺依赖、错误类型和非规范 payload 不发布对象。纯哈希不写入对象。

`mktree` 读取 `100644 wasm ID<TAB>PATH`，也接受 `blob` 类型名；`-z` 使用 NUL 分隔。存储的是平面路径映射，没有 Git 目录对象、Unix 模式或符号链接。重复路径、前缀冲突、非 Wasm 对象和缺失对象都拒绝。

`write-tree` 从完整 index 发布不可变对象，不移动 HEAD 或修改 index。`read-tree` 只替换 index；工作文件及 HEAD 保持原字节。旧未命名模块需先通过现有 restore 流程建立明确路径。

`commit-tree` 不更新引用；可重复 `-p`、`-m`，消息之间保留空行。`update-ref` 的旧值是原子比较条件；64 个零代表要求引用不存在。引用必须指向实际 commit；已检出的分支受保护。引用发布后的日志/目录同步失败会明确报告可能已完成的范围。

`rev-list` 支持 `--all`、`--parents`、`--count`、`--first-parent`、`--reverse`、`-n/--max-count`、`A..B`、对称范围 `A...B` 和 `^REV` 排除。对称范围从两个端点可达集合中排除所有最佳共同祖先的闭包，不能在 criss-cross 历史中随意选一个 base。省略任一范围端点表示 HEAD。排序为确定的子先父后拓扑顺序，不依据不存在的作者时间。

```sh
wasm-git merge-base DIR --all LEFT RIGHT
wasm-git merge-base DIR --is-ancestor ANCESTOR DESCENDANT
wasm-git merge-base DIR --octopus --all A B C
wasm-git merge-base DIR --independent A B C
wasm-git merge-base DIR --fork-point refs/heads/upstream [TOPIC]
wasm-git rev-list DIR A...B
```

`merge-base` 的普通多端点查询将首端点与其余端点的假想合并比较；`--octopus` 则要求共同祖先出现在每个端点的历史中。`--independent` 返回无法从其他输入到达的最小端点集，重复输入只输出一次。`-a/--all` 输出全部最佳 base；新选项形式默认使用逐行 ID，未指定 all 时在多个 base 中按 ID 稳定选择一个，仅用于查询，不授权实际 merge 猜测合并 base。

旧的两个裸端点形式保留“全部 base 的 JSON 数组”输出；`--text` 可明确选择逐行形式，`--json` 可为新选项形式选择 JSON。`--is-ancestor` 不输出内容，成立退出 0，不成立退出 1。新选项形式找不到 base/fork point 也退出 1，参数或对象错误退出 2；旧 JSON 形式仍以成功的空数组表示没有共同祖先。

`--fork-point` 同时查看所选实际引用的当前 tip 和本机 reflog 中记录的旧/新 tip；只有唯一最佳 base 确实是某次记录的引用 tip 时才返回，不能从更早的普通共同祖先猜测。未给 TOPIC 时使用 HEAD。HEAD 在本模型中解析为当前分支的日志；远端 tracking 尚无历史 reflog，仅有当前 tip 可作为证据。所有查询都使用一个已验证快照，不移动 HEAD、index、工作字节或引用，也不创建假想 merge 对象。图语义参照 [Git merge-base](https://git-scm.com/docs/git-merge-base)，对象和日志仍采用 uwgit 原生格式。

分支、标签可使用 `feature/x` 这样的正常层级名称。空组件、`.`、`..`、`.lock` 后缀组件及 `refs/` 前缀不能作为分支名。名字最多 128 字节，使用 ASCII 字母、数字、`.`、`_`、`-`、`/`，首字符为字母或数字。名称与完整 `refs/heads/…`、`refs/tags/…`、`refs/remotes/…` 查询分别处理；同名候选有不同目标时报告歧义。

```sh
wasm-git symbolic-ref DIR HEAD
wasm-git symbolic-ref DIR --short HEAD
wasm-git symbolic-ref DIR HEAD refs/heads/topic
wasm-git check-ref-format --branch feature/x
```

`symbolic-ref` 只改变 HEAD 指针；不切换工作文件或 index，也不创建目标引用。它可指向尚未出生的新分支。需要同步工作区时使用 switch。跨工作树占用保护与 pending 操作保护同样适用。

## 批量读取原始对象

```sh
printf 'HEAD\nHEAD^{tree}\nHEAD:modules/a.wasm\n' | wasm-git cat-file DIR --batch-check
printf 'HEAD:modules/a.wasm\n' | wasm-git cat-file DIR --batch > /tmp/objects.bin
printf 'info HEAD\ncontents HEAD:modules/a.wasm\nflush\n' | wasm-git cat-file DIR --batch-command --buffer
```

对象请求可使用完整 ID、唯一对象前缀、commit 修订、`REV^{tree}` 或 `REV:PATH`。`--batch` 输出 `ID TYPE LENGTH`、分隔符、精确 payload 字节、分隔符；长度只计算 payload，不含 uwgit 对象 envelope。`--batch-check` 只输出首部。`--batch-command` 接受 `info`、`contents`、`flush`。

`-z` 只将输入分隔符改为 NUL；`-Z` 同时使用 NUL 输入和输出。二进制 payload 不做 UTF-8 转换。不存在或歧义的对象产生对应记录；对象库损坏仍失败，不伪装成缺失对象。单个请求最多 8192 字节。

## Wasm 差异与历史

```sh
wasm-git diff-files DIR --name-status -z
wasm-git diff-index DIR HEAD --cached
wasm-git diff-tree DIR OLD NEW --exit-code -- modules/
wasm-git blame DIR HEAD --file modules/a.wasm --range 8:24
wasm-git shortlog DIR HEAD --group path -n -s
wasm-git range-diff DIR BASE..OLD NEW_BASE..NEW
```

三个底层 diff 入口分别比较 index/工作文件、指定提交/index 或工作文件、两个已命名提交树，复用产品的 Wasm 审计和原字节报告。支持 `--name-only`、`--name-status`、`-z`、`--exit-code`、`--quiet`、格式及标准配置；`--` 后选择精确路径、目录前缀或 `.`。状态是新增、删除或修改；改名保持删除加新增。`--quiet` 在有变化时退出 1 且不输出内容。

`blame` 追溯物理字节的来源候选。每个结果给出 tip 区间、来源提交与来源区间，并实际核对两边字节相等。合并中只要有未改变的父侧可继承，就继续追溯该父侧；多个可继承父侧都保留。没有可继承父侧时归于当前提交，文件缺席构成引入边界。重复字节的确定性编辑对齐不证明历史身份或行为等价；不生成仓库未保存的作者信息。资源预算不足返回明确 frontier，而不伪造归属。

`shortlog` 按实际改变的模块路径或提交 subject 分组。默认检查所有父侧并按提交去重；`--first-parent` 明确选第一父链。它不使用虚构的作者或邮箱。

`range-diff` 对两个显式 `BASE..TIP` 系列比较每条路径的原字节前后转换。唯一相同转换才配对；重复转换显示所有候选，改变的转换分别显示移除和新增，不猜补丁等价。默认附带修改模块的 Wasm 审计；`--no-audit` 省略详报。默认要求线性范围，`--first-parent` 可明确投影 merge；提交数和比较字节预算超限明确失败。

## 多工作树

```sh
wasm-git worktree DIR add NEW_DIR -b feature/topic
wasm-git worktree DIR add NEW_DIR EXISTING_BRANCH
wasm-git worktree DIR list --porcelain -z
wasm-git worktree DIR lock LINKED_DIR --reason 'retain review'
wasm-git worktree DIR unlock LINKED_DIR
wasm-git worktree DIR move LINKED_DIR NEW_DIR
wasm-git worktree DIR remove LINKED_DIR
wasm-git worktree DIR prune -n
wasm-git worktree DIR repair MOVED_DIR
```

各目录独立保存 HEAD、index、工作字节及本地冲突状态；对象、分支、标签、upstream、远端跟踪及恢复日志使用共同存储。跨目录的写操作使用共同 writer 锁；同一分支不能同时被不同工作树占用。旧客户端不能打开采用共享目录扩展的新 linked worktree。

`add -b NAME [REV]` 建立新分支；无 `-b` 时可选择现有分支。只给目录时按目录 basename 选择或创建分支。旧未命名历史需要 `--legacy-path` 明确路径。目标必须是新目录。

`remove` 默认拒绝脏 index/工作文件、untracked 文件及本地 stash。`--force` 明确丢弃这些普通文件；符号链接、特殊文件、嵌套仓库、锁定的工作树仍拒绝。对象与分支保留。主工作树和当前调用目录不能被 remove/move。

`move` 保留目录中的原字节，更新注册信息并清理迁移后的 index 锁。外部手工移动后使用 `repair`；原路径仍存在时不接管其注册。缺失目录可用 prune 清除注册；锁定记录需先显式 unlock。注册和 HEAD 的多文件 I/O 失败可能需要 repair，不承诺跨文件断电事务。

## 注释与合并工具

```sh
wasm-git notes DIR add -m 'reviewed bytes' HEAD
wasm-git notes DIR append -m 'follow-up' HEAD
wasm-git notes DIR --ref sdk list
wasm-git notes DIR show HEAD
wasm-git notes DIR copy SOURCE TARGET
wasm-git notes DIR remove TARGET
wasm-git mergetool DIR --output NEW_DIR
wasm-git mergetool DIR --output NEW_DIR --tool PROGRAM --stage -- modules/a.wasm
```

注释命名空间保存为 `uwgit-notes-NAMESPACE` 分支上的普通 Wasm 文件树；每个注释是带有原始 UTF-8 文本的规范 custom-section 模块。注释可随 clone、bundle 及显式分支 push/fetch 传输，不改变当前 HEAD、index 或工作文件。bundle 的现有 unbundle 接口只发布用户选择的一个目标分支；其他注释分支需明确恢复其已导入 commit 引用。

add 默认拒绝覆盖，`-f` 明确覆盖；append 保留空行；copy 默认保护已有目标。remove 多目标先完整验证，再发布一个新注释提交。注释文本最多 1 MiB，目标必须是已存储的原生对象。当前检出的注释分支受共同分支占用保护。

mergetool 需要显式记录的 pending 冲突。它冻结 base/ours/theirs 的原始模块，导出缺席侧为 null，生成 manifest。可选择冲突路径；缺失或不匹配的选择器在创建目录前拒绝。每个文件使用独立导出目录，路径前缀转换不会令输出文件相撞。

`--tool PROGRAM` 直接调用程序，不解析 shell 字符串。环境提供存在侧的 `BASE`、`LOCAL`、`REMOTE`，以及输出 `MERGED` 和逻辑路径 `UWGIT_PATH`；缺席侧不制造空 Wasm 文件。工具 stdout/stderr 留在导出目录。退出失败、修改输入、缺失输出、符号链接输出或非 Core Wasm 输出都不进入 index。

`--stage` 仅更新选定结果的 index 条目，保留其他暂存项和工作文件。显式 `--delete PATH` 表示删除该冲突项，工具不得同时生成 MERGED。发布前重新核对完整 index、pending 记录和原 HEAD。随后仍需审阅完整暂存树，并显式执行对应操作的 `--continue --resolved-index`；命令不替用户完成续作或推断其他非冲突改动。

## 清理与维护

```sh
wasm-git clean DIR -n -d
wasm-git clean DIR -f -X -e keep.log
wasm-git clean DIR -f -x -- generated/
wasm-git gc DIR
wasm-git gc DIR --prune=now
wasm-git maintenance DIR run --task verify
```

clean 必须给出 dry-run 或 force。默认遵循 `.gitignore` 与 `.uwgitignore`；`-x` 包括忽略文件，`-X` 仅选择忽略文件，`-e` 额外排除。默认不进入不含受控文件的 untracked 子目录；`-d` 或明确路径可选择它们。受控条目、`.uwgit`/`.git` 元数据、嵌套仓库、符号链接和特殊文件保留。删除前核对整个计划，并在每次删除前重查原字节摘要；中途失败报告已完成的路径。

gc 默认只报告计划；只有 `--prune=now` 且未给 `-n` 时才删除。它保留分支、标签、fetched 分支/标签、reflog、stash base 及注释目标的闭包；存在辅助恢复状态或 linked worktree 注册时采取保守整库保留。先删除不可达子提交，再到父提交、tree 和 blob，每个中断前缀仍有完整剩余对象图。当前没有 pack 压缩、reflog 过期或时间型自动 prune。

maintenance 支持 verify 和 gc，未实现的任务明确拒绝。所有维护输出、编译产物及分轮测试结果留在任务目录，不进入源码版本控制。

## 覆盖范围

上述各入口是明确的原生 Wasm 语义子集。全部 Git 选项和全部 plumbing 尚未完成；仍需 detached HEAD、交互式/保留 merge 拓扑的 rebase、多目标 replay 队列、更多 pathspec 与引用事务、索引标志、浅层/稀疏操作、签名、pack 与其他底层命令。准确状态持续记录在[命令能力矩阵](git-command-coverage.md)。

## 合并策略

```sh
wasm-git merge DIR TARGET --no-ff -m 'retain integration boundary'
wasm-git pull DIR --no-ff -m 'reviewed integration'
wasm-git merge DIR TARGET --squash
wasm-git commit DIR -m 'reviewed squashed change'
```

`--no-ff` 在已有 HEAD 且目标为后代时仍创建实际双父提交；已经包含的目标保持无操作。未出生分支明确拒绝此策略。它与 `--ff-only` 互斥，消息仍需显式给出。

`--squash` 将完整可合成结果放入 index 和工作文件，保留原 HEAD、不建立 pending、不创建提交。随后普通 commit 只有原 HEAD 这一个父提交。冲突时不发布部分结果；脏状态、untracked 阻挡、互斥选项及头指针/index 租约失败均拒绝。无 index 时，实际存在的工作文件仍按 untracked 保护。
