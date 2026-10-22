# Git 常用命令覆盖与当前缺口

在此前能力盘点基础上，已补充 checkout 的分支与显式路径入口、共享路径选择器和按路径 reset。
另已增加 merge／pull 的 --ff-only、cherry-pick／revert 的显式完整 index 单父解决、持久化分支 upstream、显式录制的单目标冲突续作，以及线性 rebase 的持久重放队列；旧 checkout 独占导出语法也继续可用。
随后增加已提交树、引用、对象统计和 HTTP/SSH 远端广告的五个只读查询入口。
另已增加基于实际标签历史的 describe 与原字节 archive，描述名可作为修订重新查询和导出。
历史定位另支持不切换工作区的 bisect 会话，保存用户 good/bad/skip 判断并明确报告跳过歧义。
“部分支持”表示下表所列流程可用，不表示兼容 Git 的全部选项、状态或数据格式。

## 常用能力矩阵

| 能力 | 当前状态与可用形式 | 主要缺口或行为差异 | 源码定位与 Git 参考 |
|---|---|---|---|
| 本地分支 | 部分支持：列出、从 REV 创建、`-d/-D` 删除、`-m` 重命名、`-u/--set-upstream-to`、`--unset-upstream`、`-vv` JSON；保护当前分支和未合并提交。 | 已增加 `-r/-a`、`-f`、`-M`、`-c/-C`；仍缺列表筛选/排序/格式的其他选项。名称是最多 128 字节的受限 ASCII，支持 `feature/foo` 层级名称并保护其他工作树占用。`-d` 优先检查已验证的 upstream，没有可用 upstream 时检查 HEAD。 | [porcelain.rs](../src/porcelain.rs)、[repository.rs](../src/repository.rs)；[Git branch](https://git-scm.com/docs/git-branch)。 |
| 切换分支 | 部分支持：`switch DIR NAME`、`switch DIR -c NAME [REV]`；有 index 时同步整树，保护 untracked。 | 要求整个 index/worktree 干净，不能携带不受目标影响的脏修改；已增加 detach、orphan、上一检出身份与 `switch -`；仍无自动 remote tracking。没有 index 时只切引用，不自动物化工作文件。 | [porcelain.rs](../src/porcelain.rs)；[Git switch](https://git-scm.com/docs/git-switch)。 |
| 自动合并 | 部分支持：`merge DIR REV -m MESSAGE`；已合并则不变、可快进则快进，否则用唯一 merge base 做保守三方合并；支持完整文件树，`--ff-only` 拒绝分叉。 | 已补 `--no-ff` 的双父强制合并及 `--squash` 的完整树暂存；仍无 octopus、普通 `--no-commit` 及其他全部策略选项。自动文件内组合有明确 Wasm 结构限制，不证明行为符合用户意图。 | [repository.rs](../src/repository.rs)；[Git merge](https://git-scm.com/docs/git-merge)。 |
| 手工解决合并 | 已支持显式流程：不可变 TARGET_ID，加 `--resolved-index --expect-head HEAD_ID`，可再绑定分支；发布完整暂存树的双父提交，保留工作区。旧单模块 `--resolved WASM` 仍可用。 | 只适用于明确审定的分叉合并；不是普通 `commit` 自动读取 pending merge 状态。暂存树必须已存在，空 index 与缺失 index 分开处理。 | [tree_resolution.rs](../src/tree_resolution.rs)、[repository.rs](../src/repository.rs)；[Git merge](https://git-scm.com/docs/git-merge)。 |
| 冲突后的续作状态 | 已有 index 的 merge/pick/revert/rebase 显式录制统一使用原生队列、自动 stage 0/1/2/3 和物化检查点；continue、skip（merge 除外）、abort、quit。pick/revert 多目标与范围同样可用。 | 旧 version 1 及无 index 的纯对象模式继续保留元数据续作，需要自行准备完整 index；没有 Git MERGE_HEAD。新记录按原/新字节恢复并保护后来的编辑，最终才发布 HEAD。 | [录制冲突](pending.md)、[rebase](rebase-pending.md)、[原生队列](replay-queue.md)、[repository_sequencer.rs](../src/repository_sequencer.rs)。 |
| cherry-pick / revert | 支持多个裸 REV、范围/排除/父集合、stdin、reverse、mainline、消息、no-commit、empty stop/drop/keep、allow-empty、keep-redundant-commits；pick 另支持 -x、ff。原生 Wasm 三方组合，真实单父进度链；no-commit 使用 tree 并保留起始暂存内容。 | 此处 -m MESSAGE 是消息参数，选父使用 --mainline N。没有作者/时间/签名元数据、交互编辑、外部合并策略或全部 Git 选项。裸单目标默认继续 stateless，可显式 --sequence 选择持久队列。 | [队列合同](replay-queue.md)、[replay_commands.rs](../src/replay_commands.rs)、[porcelain_replay.rs](../src/porcelain_replay.rs)。 |
| rebase | 线性单父 rebase、upstream/onto、唯一 fork；--record-conflict 冻结原序列并自动建立阶段索引，审定后 continue、逐源 skip、整体 abort 或 quit。空队列复用实际 onto；全部检查点完成后一次发布最终 tip。 | 仍缺交互式、保留 merge 拓扑、root replay、自动 patch-equivalence 和 todo 编辑。原 HEAD 保持到完成；旧 journal/纯对象模式保留原来的元数据续作，新工作区模式自动同步当前和最终结果。 | [rebase 契约](rebase-pending.md)、[rebase_commands.rs](../src/rebase_commands.rs)、[repository_sequencer.rs](../src/repository_sequencer.rs)；[Git rebase](https://git-scm.com/docs/git-rebase)。 |
| restore | 部分支持：index→worktree、source、staged/worktree、精确文件、目录、`.`、`--overlay` 与独占导出。每个显式选择器先完成匹配；未知路径明确失败。 | 已共享 glob/literal/icase/top/exclude 路径选择；已支持 unmerged stages 的 `--ours/--theirs` 工作文件恢复；仍无 attr magic 或交互 patch。导出 --file 仍精确选择一个模块。 | [porcelain.rs](../src/porcelain.rs)；[Git restore](https://git-scm.com/docs/git-restore)。 |
| reset | 部分支持：soft/mixed/hard 整树回退；`reset DIR [REV] -- PATH...` 仅恢复所选 index，HEAD 和工作文件不变。 | 无 keep/merge/patch；路径模式不能组合整树模式，默认 HEAD 在首个提交前明确拒绝。 | [porcelain.rs](../src/porcelain.rs)；[Git reset](https://git-scm.com/docs/git-reset)。 |
| checkout | 部分支持：`DIR BRANCH`、`DIR -b NAME [REV]`；`DIR -- PATH...` 从 index 恢复工作路径；`DIR REV -- PATH...` 按 overlay 恢复 index+worktree；旧 REV NEW_FILE [--file PATH] 独占导出。 | 已支持 detached HEAD、orphan 与明确 tag/commit 的 detach；仍无 force 或隐式路径猜测；分支模式继承 switch 的干净工作区要求和无 index 时只切引用的行为。恢复已有路径必须用明确的 `--`。 | [checkout.rs](../src/checkout.rs)、[porcelain.rs](../src/porcelain.rs)；[Git checkout](https://git-scm.com/docs/git-checkout)。 |
| upstream 与默认 pull/push | 部分支持显式分支关联、按关联选择默认 pull 的 remote/branch、push 的默认 remote 和 simple 同名检查；`push -u` 单分支成功确认后保存关联；`rev-parse` 支持 `[NAME]@{u}`/`[NAME]@{upstream}`。无关联时保留 origin/当前同名分支的旧回退。 | 从 tracking 创建 branch/switch 不自动建立关联；没有 push.default/pushRemote 等配置模式。新 push 目标的 fetched tracking 仍需 fetch 后可查询；`-u` 不绕过 simple 异名保护。 | [remote.rs](../src/remote.rs)；[Git branch](https://git-scm.com/docs/git-branch)、[Git push](https://git-scm.com/docs/git-push)。 |
| clone / bundle | 已支持本地和 HTTP/SSH 完整 clone、离线 bundle/unbundle，保留分支、标签、HEAD 和已验证对象；网络 clone 配置 origin 并为已提交的初始 HEAD 建立 upstream。 | 本地 upstream 配置不传输；clone 不自动建立 index 或工作文件，需显式 restore；无 shallow、partial、single-branch、sparse、递归 submodule 等 clone 模式。 | [repository.rs](../src/repository.rs)、[remote.rs](../src/remote.rs)；[Git clone](https://git-scm.com/docs/git-clone)。 |
| 历史与 reflog | 部分支持 DAG log、show、标签、rev-parse、reflog，以及 Wasm 字节区间 trace。修订支持 ID/前缀、分支/标签/tracking、`~N/^N`；独立的 rev-parse upstream 别名查询实际 fetched tip。 | 已支持 upstream 后续祖先运算、`HEAD@{n}`、`@{-N}` 与 commit peel；仍无日期 reflog、ORIG_HEAD 和常见日志筛选/graph 接口；trace 是物理字节证据，不是 Git blame。 | [repository.rs](../src/repository.rs)；[Git reflog](https://git-scm.com/docs/git-reflog)。 |
| stash | 部分支持 push/list/apply/pop/drop 与单现存工作文件导出；分别保存、恢复 index 和 tracked 工作字节，含删除及非 Wasm 脏字节。 | 不收集 untracked；apply/pop 要求当前 index/worktree 干净；无 include-untracked、stash branch/show 等接口。 | [porcelain.rs](../src/porcelain.rs)；[Git stash](https://git-scm.com/docs/git-stash)。 |
| 已提交树与引用查询 | 部分支持：ls-tree 的实际平面树/JSON/路径/NUL，show-ref 的 HEAD/namespace/verify/quiet/hash，for-each-ref 的 prefix/glob/format/sort/count。 | 不合成目录对象或 mode；旧 unnamed 提交仅 JSON 保留真实 blob。格式 atom 与 glob 有明确子集，无 Git 全部 modifier/field/sort/filter。 | [query_commands.rs](../src/query_commands.rs)、[查询契约与验证](queries.md)；[Git ls-tree](https://git-scm.com/docs/git-ls-tree)、[Git show-ref](https://git-scm.com/docs/git-show-ref)、[Git for-each-ref](https://git-scm.com/docs/git-for-each-ref)。 |
| 对象统计与远端广告 | 部分支持：count-objects JSON/verbose/human-readable，ls-remote 的 HTTP(S)/SSH、配置 remote、namespace/glob/symref/exit-code/JSON。 | 统计逻辑 payload/envelope 字节，非 Git 压缩 pack 或分配块。广告只查询引用，不下载或验证其对象；明确标注验证范围。无本地路径 ls-remote。 | [repository.rs](../src/repository.rs)、[remote.rs](../src/remote.rs)；[Git count-objects](https://git-scm.com/docs/git-count-objects)、[Git ls-remote](https://git-scm.com/docs/git-ls-remote)。 |
| 标签描述与归档 | 部分支持：describe 的轻量标签、精确/祖先/first-parent、唯一缩写、match/exclude/reset、always/long/JSON；archive 的 ustar、prefix、路径选择、完整 tree ID 与显式 legacy 命名。 | 没有 annotated 标签、日期或 describe --all/--contains/dirty；平分按 ASCII 名称。archive 无 ZIP/压缩/远端/attributes，固定元数据为导出策略，不猜原 mode/time。 | [describe_commands.rs](../src/describe_commands.rs)、[archive_commands.rs](../src/archive_commands.rs)、[契约与验证](describe-archive.md)；[Git describe](https://git-scm.com/docs/git-describe)、[Git archive](https://git-scm.com/docs/git-archive)。 |
| 历史二分定位 | 部分支持：bisect start 的冻结 bad/good 端点、no-checkout、first-parent；good/bad/skip、status/next/log/reset。按实际祖先集合选择平衡候选，跳过导致歧义时列出完整嫌疑。 | 不切换 HEAD/index/worktree，不运行脚本；初始 good 须为 bad 祖先，bad 沿祖先链收缩。无自动 checkout、路径筛选、范围 skip、自定义 terms 或 Git shell 日志 replay。 | [bisect_commands.rs](../src/bisect_commands.rs)、[repository.rs](../src/repository.rs)、[契约与验证](bisect.md)；[Git bisect](https://git-scm.com/docs/git-bisect)。 |
| 原生对象 plumbing | 已有 hash-object、mktree、write-tree、read-tree、commit-tree、update-ref、rev-list、symbolic-ref、check-ref-format 与 cat-file 批量原字节读取。 | 自有 Wasm/type/tree/commit 格式；分支/标签已有持久批量引用事务及 --batch-updates 逐项拒绝。还缺任意 Git blob、批量符号引用、任意引用命名空间、全部批量格式 atom、所有修订语法及其他 plumbing。 | [对象命令](native-commands.md)、[引用事务](ref-transactions.md)、[plumbing_commands.rs](../src/plumbing_commands.rs)、[object_batch.rs](../src/object_batch.rs)。 |
| 原生索引与冲突 stages | read-tree 的单树/empty/三方 stages/prefix/update/dry-run；ls-files stage/unmerged/modified/deleted/others/ignored/killed、排除规则、标签与格式；checkout-index 物化/prefix/stdin/stages/temp；write-tree prefix；update-index 工作路径、cacheinfo、index-info、stdin、remove 与 dry-run；merge-index 原生 Wasm 合成。 | 文件和目录冲突保留各侧图像；未解决项阻止发布树。所有新录制工作区操作已自动填充 stages；旧 journal/纯对象模式保留显式准备。已支持 assume/skip/原图像有效性标志、intent-to-add 与 refresh；仍缺完整稀疏 index、ls-files 的 directory/abbrev/EOL/resolve-undo、checkout-index stat cache、read-tree 全部携带规则。 | [索引合同](index-stages.md)、[index_plumbing.rs](../src/index_plumbing.rs)。 |
| 共同祖先与对称范围 | merge-base 的全部最佳 base、octopus、independent、is-ancestor、reflog fork-point；rev-list 支持 `A...B`。 | 旧双端点 merge-base 保留 JSON 全结果；tracking 没有历史 reflog 时不猜旧 fork point。提交无时间，结果按真实拓扑及 ID 排序。 | [图查询契约](native-commands.md)、[merge_base_commands.rs](../src/merge_base_commands.rs)；[Git merge-base](https://git-scm.com/docs/git-merge-base)。 |
| 底层差异查询 | diff-files、diff-index、diff-tree 比较 index/工作文件/命名树；支持路径筛选、NUL、名称/状态及变化退出码，复用 Wasm 审计。 | 不推断 rename；旧未命名历史继续使用 diff --repo。已有共享路径选择器；没有完整文本行、mode 或 combined unmerged diff。 | [差异命令](native-commands.md)、[diff_plumbing.rs](../src/diff_plumbing.rs)。 |
| 多工作树 | worktree add/list/remove/move/lock/unlock/prune/repair；共享对象/refs，独立 HEAD、index 和工作文件，保护跨树分支占用。 | 已支持 detached worktree，仍无 orphan worktree；移除对符号链接、特殊文件和嵌套仓库采取保护。多文件 I/O 失败可能需 repair。 | [工作树契约](native-commands.md)、[repository_worktrees.rs](../src/repository_worktrees.rs)。 |
| Wasm 字节来源 | blame 给出 tip/来源区间和提交候选；核对原字节相等，支持所有父侧或 first-parent 及预算 frontier。 | 不包含仓库未保存的作者，不证明历史身份或语义等价；重复对齐可能有多个候选。 | [来源契约](native-commands.md)、[blame.rs](../src/blame.rs)。 |
| 历史摘要与系列比较 | shortlog 按实际改变路径/subject 分组；range-diff 比较两个系列的原字节路径转换，并给出 Wasm 审计。 | 不虚构作者；range-diff 不猜修改补丁的等价配对，重复转换保留歧义，merge 需明确 first-parent。 | [历史查询契约](native-commands.md)、[repository_history_tools.rs](../src/repository_history_tools.rs)。 |
| 可传输注释 | notes list/show/add/append/copy/remove 与命名空间；注释存为专用原生分支中的真实 Wasm 模块，可经既有传输共享。 | 无交互编辑、注释 merge/rewrite；unbundle 现有单目标引用规则仍适用。 | [注释契约](native-commands.md)、[repository_notes.rs](../src/repository_notes.rs)。 |
| 外部合并工具 | mergetool 导出冻结三方模块，调用明确程序；校验输入、index、pending、HEAD 后暂存选定结果；识别队列进度，no-commit 的 ours_kind 为真实 tree。 | 仍需审阅完整 index 并显式 continue。新录制工作区操作已自动填充 stage 0 和冲突原侧；旧 journal/纯对象模式仍需自行准备完整结果。 | [工具契约](native-commands.md)、[多目标 replay](replay-queue.md)、[worktree_tools.rs](../src/worktree_tools.rs)。 |
| 清理与维护 | clean dry-run/force、目录、忽略规则、排除与显式路径；gc 计划及显式 prune；maintenance verify/gc。 | 无交互 clean、嵌套仓库/符号链接删除、pack、reflog 过期或自动时间 prune；辅助恢复状态使 GC 保守保留。 | [维护契约](native-commands.md)、[maintenance_commands.rs](../src/maintenance_commands.rs)。 |

## 当前可用的四类操作

以下都使用本程序语法；DIR 及路径须替换为自己的仓库。真实修改前先查看 status/diff，保留仍需使用的工作字节。

1. **分支合并及显式手工解决。** 普通 merge 要求已有工作区干净。若返回冲突，先审阅报告中的不可变 target 和 old_head，
   再编辑、add/rm 得到完整暂存结果，使用报告 ID 显式提交双父合并；若开始时使用 `--record-conflict`，也可使用 `merge --continue --resolved-index`。
   此接口不会自动补入对方的非冲突变更，必须审阅并准备整个结果树，不能只解决冲突路径就假定其他路径已合并。

   ```sh
   wasm-git branch ./history topic HEAD
   wasm-git switch ./history topic
   # 编辑模块、add、commit 后，切回 main
   wasm-git switch ./history main
   wasm-git merge ./history topic -m 'integrate topic'
   # 仅在审阅冲突并准备好完整 index 后，以实际完整 ID 替换占位符
   wasm-git merge ./history TARGET_FULL_ID -m 'reviewed resolution' \
     --resolved-index --expect-head REVIEWED_HEAD_ID --expect-branch main
   ```

2. **还原选定文件或取消其暂存。** 第一条会丢弃该精确工作路径的未暂存修改，第二条只改 index；两者均不移动 HEAD。
   也可明确选择目录或 `.`；末尾 `/` 只匹配目录后代，每个参数都必须匹配，未匹配时全部拒绝。

   ```sh
   wasm-git restore ./history -- modules/a.wasm
   wasm-git restore ./history --staged -- modules/a.wasm
   ```

3. **明确回退本地分支。** soft 保留 index/工作区，mixed 替换 index、保留工作区，hard 两者都替换。
   `reset --hard` 会移动当前本地分支并丢弃 tracked 的暂存和工作修改；需要保留时先保存它们。
   stash 不保存 untracked 文件，挡路的 untracked 会令 hard reset 失败。

   ```sh
   wasm-git status ./history
   wasm-git stash ./history push -m 'preserve tracked local work'
   wasm-git reset ./history --hard REVIEWED_COMMIT_ID
   ```

4. **保留旧历史的反向提交。** revert 创建新的单父提交，不把分支直接退回旧 tip；仍可能冲突。
   合并提交需用 `--mainline N` 明确选父，本程序的 `-m` 用于消息。

   ```sh
   wasm-git revert ./history BAD_COMMIT_ID -m 'reverse reviewed change'
   ```

clone 后要建立完整工作区，可另外执行 `restore DIR --source HEAD --staged --worktree`。
checkout 的旧导出形式用于检查原字节新副本；还原已有路径使用 `checkout DIR [REV] -- PATH...`，切分支使用 `checkout DIR NAME` 或 switch。

## 已实现的工作流

1. **第一阶段已实现：checkout 分流与共享路径选择。** 分支切换、新分支、index 路径恢复、修订路径恢复和旧导出语法明确区分，
   复用 switch/restore 的锁、CAS、预检与 untracked 保护。选择器覆盖精确文件、目录和 `.`；未匹配或空分隔符选择直接拒绝。
   按路径 reset 仅改所选 index。checkout 修订路径采用 overlay，保留不相关的 source 缺项，只替换与选中源路径有前缀冲突的受控条目。
2. **第二阶段已实现：replay 的显式单父解决和 ff-only。** cherry-pick/revert 绑定不可变目标、预期 HEAD 及可选分支，以完整 index 发布单父提交，
   不修改 index 或工作文件，不要求已有 pending 状态。merge --ff-only 在分叉时零发布；pull 的 fetch 对象和 tracking 可保留，但不改变本地 HEAD/index/worktree。
   该阶段不包含 rebase 手工步骤替换；后续第五阶段补充。详细范围见[快进约束与单父手工重放](replay-resolution.md)。
3. **第三阶段已实现：分支 upstream。** 独立本地配置保存分支与 remote/branch 的关联；分支及 remote 重命名会移动关联，删除先清关联，避免名称复用意外继承。
   默认 pull/push、显式设置和查询接入同一模型；push -u 在精确远端确认后，以本地 tip 和旧关联双重 CAS 保存。
   自动 tracking 推断、其他 push 策略仍未实现。
4. **第四阶段已实现：单目标持久冲突续作。** 显式录制后绑定操作种类、分支、原 HEAD、不可变目标、mainline、消息和原 index。
   发布前先保存 prepared 提交及原始 index 摘要，重试识别同一提交并补齐 reflog/清理，不创建重复提交；abort 的恢复在 writer 锁中完成。
   普通默认冲突继续 stateless；该阶段仅支持单目标，rebase 队列由第五阶段补充。detached/orphan 的多形态 HEAD 和传输扩展已加入，见 [HEAD 契约](head-and-pathspec.md)。
   使用边界和结果见[单目标续作验证](pending.md)。
5. **第五阶段已实现：线性 rebase 的持久队列。** 明确录制后冻结 upstream、onto、原单父提交序列及每步进度，冲突期间不移动分支。
   continue 保存当前步骤的完整 index，随后自动重放直到下一冲突或最终 tip；skip 只跳过当前步骤后继续。
   abort 恢复最初 index/受控工作文件，quit 保留当前文件；每个手工步骤以其实际进度提交为 ours 重建四侧审计。
   交互 rebase 与保留 merge 拓扑仍未实现；多目标 pick/revert 已由后续原生队列补充，具体边界见[rebase 续作验证](rebase-pending.md)。
6. **第六阶段已实现：只读对象与引用查询。** ls-tree/show-ref/for-each-ref/count-objects 使用单个已验证快照，区分旧单模块与实际命名树，准确保留对象类型和长度；ls-remote 仅广告查询且不建立本地状态。选项子集、默认格式、退出码和统计 roots 见[查询契约与验证](queries.md)。
7. **第七阶段已实现：标签描述与原字节归档。** describe 按真实祖先闭包计算标签距离，支持生成名称的修订回读；archive 导出单快照实际 Wasm 字节，保留未知内容，显式报告固定导出元数据和 legacy 命名。范围及验证见[describe/archive](describe-archive.md)。
8. **第八阶段：不切换工作区的历史二分。** bisect 使用持久的完整提交判断选择候选，不把跳过提交当成 good/bad，也不让引用推进替换已冻结端点；状态与范围见[bisect 契约](bisect.md)。

9. **原生索引标志与多目标 replay。** 索引 version 4 保存 assume/skip/图像有效性与无图像的 intent-to-add；读旧版本、批量失败保持、显式物化和 commit -a 接入原字节模型。pick/revert 冻结列表或范围，自动生成 stages，支持 no-commit、empty/ff、逐项续作及工作区检查点恢复。详见[索引标志](index-flags.md)与[队列契约](replay-queue.md)。

10. **录制冲突统一接入原生 stages。** 工作区 merge/pick/revert/rebase 录制自动准备非冲突增删和原始冲突侧，保留正确父关系；rebase 冻结 fork/onto/源序列，带逐写入前缀恢复。skip 只撤销当前来源，保护无关暂存工作副本、初始脏字节、稀疏缺席和后续编辑；旧 journal 与纯对象模式继续可读。

11. **分支与标签的持久批量引用事务。** update-ref 的单引用/`--stdin` 共用 CAS 和持久提交决定；混合 update/create/delete/verify、NUL、显式 prepare/commit/abort 与 EOF 规则可用。准备时保护 worktree、验证整批对象和最终名称结构，恢复在共享锁中先检查原/新像，再幂等安装引用、upstream 和固定日志。见[引用事务](ref-transactions.md)。

12. **原生引用批处理的逐项拒绝。** `--batch-updates/-0` 只过滤可解析请求的语义拒绝，正确项冻结后沿用同一持久事务和恢复检查；格式错误、仓库损坏、锁及 I/O 错误仍使整笔操作失败。拒绝结果在 commit 后输出，prepare/abort/EOF 保持和 Git 独立对照均有回归覆盖。单独 prepare 后 EOF 也明确丢弃未提交事务。见[引用事务](ref-transactions.md)。

## 全选项与底层命令的后续范围

当前已补齐此前“无入口”的九类工具，并增加一批对象、引用和差异 plumbing。仍不能将此矩阵称为全部 Git 命令及选项已经完成。已补充 [HEAD、分支与共享路径选择](head-and-pathspec.md)。已补充[索引标志与意向条目](index-flags.md)、[多目标 replay 与自动 stages](replay-queue.md)。剩余范围包括全修订语法、批量符号引用/任意命名空间及网络多引用原子发布、交互式及保留 merge 拓扑 rebase、浅层/完整稀疏工作区、外部 FSMonitor/split-index、签名与 pack，以及其他尚未支持的选项和底层命令。每项需有实际 Wasm 行为和失败保持测试，不能仅建立名称或静默接受无效选项。

索引扩展的 stages、批量预检、文件/目录分歧和工作区保护合同见[原生索引](index-stages.md)。
