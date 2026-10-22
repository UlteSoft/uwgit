# 录制冲突、原生 stages 与续作

普通单目标命令保持 stateless：冲突只输出 JSON、退出 2，不改 index、工作文件或建立记录。
已有 index 时，显式 `--record-conflict` 使用原生冻结队列，自动准备完整步骤的 stage 0 和真实冲突侧。
merge 使用 version 3 journal；单目标 pick/revert 使用兼容的 version 2。对象、Wasm 图像、引用和传输仍全部由 uwgit 实现。

```sh
wasm-git merge DIR REV --record-conflict -m MESSAGE
wasm-git cherry-pick DIR REV --record-conflict [--mainline N] [-m MESSAGE]
wasm-git revert DIR REV --record-conflict [--mainline N] [-m MESSAGE]
wasm-git ls-files DIR --unmerged
wasm-git restore DIR --ours -- modules/a.wasm
# 编辑并审阅完整 index，解决每个未解决项
wasm-git add DIR modules/a.wasm
wasm-git merge DIR --continue --resolved-index
# 以下是其他互斥选择
wasm-git merge DIR --abort
wasm-git merge DIR --quit
```

## 完整结果与历史

录制前要求受控 index/worktree 干净，允许 skip-worktree 承诺的缺席。
目标、检出身份、原 HEAD、mainline、消息、原 index 编码和受控工作字节在同一流程中绑定；后续引用移动不会更换来源。
所有非冲突新增、修改、删除进入 stage 0；冲突的 base/ours/theirs 原字节进入 stage 1/2/3。
缺席侧保持缺席，不能用空 Wasm 代替；目录/文件分歧保留整个冲突组。工作侧显示 ours，必要时展开稀疏冲突路径。
`mergetool` 导出同一冻结三方输入，可明确暂存所选结果；其他非冲突项已经在新记录的 index 中。

continue 必须显式带 `--resolved-index`，并且没有未解决项或 intent-to-add。
它采用用户审定的**整个**暂存树，用户明确删除的路径不会被偷偷补回。
merge 保留原 HEAD 与 target 两个有序父提交；pick/revert 保留一个父提交。
四侧 Wasm 原字节、摘要、审计和差异进入 `manual_resolutions`，最后一个手工结果另提供 `tree_manual_resolution`。
手工暂存以外的编辑不会自动进入提交；不受后续结果影响的工作字节保留。
成功后 index/工作文件先完成可恢复检查点，最终 HEAD 才一次发布；完整状态语义见[原生队列](replay-queue.md)。

pick/revert 的 skip 跳过当前目标；单目标结束后不制造提交，返回 unchanged。merge 没有 skip。
skip 只撤销当前来源产生的工作区变化，无关新暂存文件保留为 untracked，无关编辑保留。
若后续自动步骤会覆盖这些编辑，先拒绝，不推进对象、index、journal 或 HEAD。
abort 恢复操作开始时 index 的原编码与原受控工作字节，包括稀疏缺席；操作已物化并记录的路径可清除，后来新增的无关文件保留。
目录、symlink 或新文件阻挡原路径恢复时先拒绝。quit 只清记录，保留当前 stages、暂存内容和工作字节。

已有 pending 时，普通 commit/amend、新历史、整树 reset、分支切换、绑定分支 rename/delete 和 stash 应用会拒绝。
add/rm/mv/restore/路径 reset 可以准备审定结果；status 报告当前阶段。损坏 index 会明确显示不可用，不能伪装 clean。

## 检查点与兼容

记录严格规范 JSON，包含备份的总量限制为 64 MiB。每次读取重新验证冻结来源、父链、消息和自动组合。
先安装完整对象闭包，再保存包含每个文件和 index 的写入前后字节的检查点，然后物化、结算，最后发布引用/reflog并清理。
部分 I/O 失败保留记录；重试只接受原/新两种字节，后来的第三种编辑会被保护。
`--continue` 在修复未完成检查点或结算最终发布时可以不带 resolved-index；修复到冲突状态不会冒充已审定的解决。
引用已经发布时可补唯一 generation 的 reflog，保留后来损坏或移除的 index，不重复制造提交。
这些是确定性中断状态测试；多文件 I/O 不是断电整体事务。

原先存在的 version 1 记录继续使用原来的元数据续作，不能自动升级后猜测当前工作内容。
没有 index 的纯对象仓库也保留这个模式：不自动物化或创建 index，continue 要自行建立完整暂存树；abort 恢复 index 不存在并保留工作文件。
此模式不自动补入非冲突路径，续作不改 index/worktree。其 prepared 引用发布前仍要求同一份审定 index；发布后可修复 reflog 并清理。
未命名 legacy 历史必须先建立明确路径；程序不猜路径。记录不随 bundle/clone/HTTP/SSH 传输，已安装的对象仍遵守完整对象包规则。

固定验证见 [pending_cli.rs](../tests/pending_cli.rs)、[repository_sequencer.rs](../src/repository_sequencer.rs) 和独立 [Git 对照](../tests/git_reference_cli.rs)。
rebase 见[持久 rebase](rebase-pending.md)，剩余范围见[能力矩阵](git-command-coverage.md)。
