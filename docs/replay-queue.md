# 多目标原生 Wasm replay

cherry-pick/revert 可以冻结多个目标、范围或 stdin 中的提交选择。每一步按真实路径的原始 Wasm 图像做三方组合；
原 HEAD 保持到整个队列及工作区检查点完成，再一次发布最终 tip。对象格式、差异、合并及引用都由 uwgit 原生实现。

```sh
wasm-git cherry-pick DIR FIRST_ID SECOND_ID
wasm-git cherry-pick DIR BASE..TOP
wasm-git revert DIR BASE..TOP
printf 'FIRST_ID\nSECOND_ID\n' | wasm-git cherry-pick DIR --stdin
wasm-git cherry-pick DIR --sequence SINGLE_ID
wasm-git cherry-pick DIR -n FIRST_ID SECOND_ID
```

裸目标列表保留参数顺序、按完整 ID 去重。含范围、排除项或父集合时，在同一个已验证快照中做一次 DAG 遍历：
pick 按父先于子，revert 按子先于父；同层顺序沿用原生 rev-list 的确定性规则，不虚构时间戳。
`--reverse` 翻转冻结后的队列。最多 4096 个选择器和 4096 个结果提交；stdin 是 UTF-8 一行一项，最多 64 MiB，不能再给位置目标。
所有目标、mainline 与路径锚点先完整校验；后面的非法提交不会先安装成功前缀。

单目标未使用新队列选项时保留原来的 stateless 行为；其 `--record-conflict` 仍使用 version 1 记录。
多目标、范围、`--sequence`、`--stdin`、`-n` 等选择新的 version 2 原生队列，冲突自动记录并生成真实 stages。
原来的不可变完整 ID 加 `--resolved-index --expect-head ID` 接口仍可用。

| 选项 | 合同 |
|---|---|
| `-n/--no-commit` | 从完整当前 index 开始，可含已有暂存结果；中间进度是原生 tree，不制造合成 commit。HEAD 与 commit 对象数不变，完整结果进入 index/工作区。未受结果影响的脏编辑保留；会被覆盖的脏编辑在发布前拒绝。 |
| `--mainline N` | 为所选 merge 提交选择从 1 开始的父序号；整队列预检。根提交的缺席父侧是真正空文件映射。 |
| `-m/--message MESSAGE` | 本程序已有的消息选项，应用于每个新提交；不是 Git 的 `-m N`。未指定时 pick 沿用原消息，revert 生成包含目标 ID 的消息。 |
| `-x` | pick 消息追加原始完整来源 ID。revert 拒绝。 |
| `--ff` | pick 的当前进度就是所选父提交且路径身份兼容时，复用精确原提交；否则正常组合。不能组合 no-commit、自定义消息或 -x。 |
| `--empty stop/drop/keep` | 默认 stop 冗余结果并等待明确选择；drop 跳过因当前历史已包含而变空的修改；keep 保存真实空结果提交。 |
| `--allow-empty` | 允许原来就是空修改的提交；原本非空但 replay 后变空仍受 empty 策略控制。原本空提交不会仅因 drop 而默默跳过。 |
| `--keep-redundant-commits` | `--empty=keep` 的兼容别名。 |

no-commit 不接受消息、-x、ff 等提交身份选项。未知、重复、互斥参数明确拒绝。

## 冲突、解决与撤销

```sh
wasm-git status DIR
wasm-git ls-files DIR --unmerged
wasm-git restore DIR --ours -- modules/a.wasm
# 编辑后准备并审阅整个步骤结果；删除使用 rm
wasm-git add DIR modules/a.wasm
wasm-git cherry-pick DIR --continue --resolved-index
# 也可以只跳过当前目标，或恢复整个操作起点，或忘记 journal
wasm-git cherry-pick DIR --skip
wasm-git cherry-pick DIR --abort
wasm-git cherry-pick DIR --quit
```

冲突自动保存 base/ours/theirs 的真实可选原字节为 stage 1/2/3，非冲突部分同时进入 stage 0。
ours 是当前队列进度；no-commit 的 ours 真实类型为 tree。缺席侧保留缺席，不用空模块代替。
工作侧先保留 ours 图像；目录/文件分歧保留完整冲突组。无法安全组合的模块保守停止，保留所有原侧。
`mergetool` 可导出、明确暂存选定结果，报告 ours_kind，仍需审阅完整 index 再 continue。

continue 要求没有未解决 stages 或 intent-to-add 的完整审定 index，将它作为当前步骤结果，再自动处理后续步骤。
未暂存编辑不自动进入提交；目标图像没有改变的路径保留实际编辑字节。遇到下一冲突或空结果再次退出 2；
全部成功返回 committed，no-commit 返回 staged，全部 skip/drop 返回 unchanged。报告提供完整 queue、cursor、步骤来源/结果及实际更新标志。

skip 放弃当前停止步骤的编辑与解决内容，回到该步骤之前的进度后继续；不能把未受控文件当受控文件删除。
abort 恢复整个操作开始时 index 的原编码及当时受控工作字节，包含 no-commit 原有暂存和脏编辑、跳过路径的缺席；
操作产生的已记录路径移除，后来新增的无关文件保留。阻挡恢复的文件类型、符号链接或目录仍会导致拒绝。
quit 只忘记 journal，不恢复任何字节。revert 使用相同控制入口，但必须匹配当前操作种类。
控制选项互斥，不能替换冻结目标、消息、策略或 mainline。

## 持久检查点与恢复

version 2 `.uwgit/pending.json` 绑定原 HEAD/检出身份、原 index、原受控工作图像、选项、完整队列、进度链与所拥有路径。
记录为严格规范 JSON，限制 64 MiB。每次读取重新核对来源、图像、对象类型、父链、消息及自动组合结果。
尚未完成的 journal 使维护与 GC 保守保留对象，其他普通历史写入口受 pending guard 约束。

每次推进先在内存准备整个成功前缀，按 Wasm→tree→父先于子 commit 顺序安装，再持久化包含原/新 index 与每个工作路径写入前后字节的检查点。
之后物化文件、保存 index、结算检查点，最后才发布最终引用/reflog并清理。
中途失败保留 journal，重试 `--continue` 只接受每一项仍为写入前或写入后的精确字节；出现后来的第三种编辑会拒绝，不能覆盖。
修复到冲突检查点时只恢复这个停止状态，不把它冒充用户已经审定的解决结果。

检查点已结算时的最终发布可直接重试，不重新读取或覆盖后来编辑的 index/工作区。
若引用已更新而 reflog/清理未完成，按 generation 补唯一 reflog，不重复制造提交。
HEAD 已改到第三种 tip 或同 tip 的另一检出分支时拒绝推进和 abort，quit 仍可清理过时记录。
多文件 I/O 不是断电整体事务；失败后可能只完成部分物化，检查点提供可校验恢复边界。

固定验证见 [replay_queue_cli.rs](../tests/replay_queue_cli.rs) 和 [repository_sequencer.rs](../src/repository_sequencer.rs) 内恢复测试：
顺序、范围、真实单父链、原字节合成、no-commit 无合成提交、连续冲突、skip/abort/quit、稀疏与标志恢复、
迟到非法目标零写入、empty/ff、每个文件及 index 写入切点、发布后补 log、篡改拒绝和独立 Git 对照。
这是确定性中断状态测试，不声称覆盖随机断电。签名、作者/时间元数据、外部策略、交互编辑与 Git 全选项仍见[能力矩阵](git-command-coverage.md)。
