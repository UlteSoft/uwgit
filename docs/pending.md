# 单目标冲突续作与中断恢复

本页描述旧单目标接口。未选择新队列选项的单目标默认冲突保持 stateless；多目标、范围及 `--sequence` 使用[多目标 replay](replay-queue.md)，自动记录 stages 和工作区检查点。

## 操作契约

```sh
wasm-git merge DIR REV --record-conflict -m MESSAGE
wasm-git cherry-pick DIR REV --record-conflict [--mainline N] [-m MESSAGE]
wasm-git revert DIR REV --record-conflict [--mainline N] [-m MESSAGE]

# 准备并审阅完整 index 后，选择以下一种操作
wasm-git merge DIR --continue --resolved-index
wasm-git merge DIR --abort
wasm-git merge DIR --quit
```

cherry-pick/revert 支持相同的续作入口，另支持单目标 `--skip`；merge 不支持 skip。
录制仅发生于实际内容冲突；成功、快进或目标已包含时不留 pending。
记录绑定操作种类、唯一 generation、原分支/HEAD、完整目标 ID、base 或 mainline/selected parent、消息、原 index 编码和 legacy 路径。
目标 ref 后续移动不能改变已录制的目标；续作不接受新的 REV、消息或 mainline。

`--continue --resolved-index` 是对**完整暂存树**的显式承诺，不表示程序已经自动识别每一个冲突被解决。
它保存所有暂存的新增、删除和其他路径；不会自动补入目标的非冲突部分。
merge 保存两个父提交，pick/revert 只以原 HEAD 为父；四侧原字节 hex、SHA、长度、审计和从两侧到结果的差异进入报告。
未暂存的脏字节、缺失文件、当前 index 均不被续作改写。

abort 在 index→writer 锁内恢复原 index 的原编码及开始时已有的受控工作文件，不移动 HEAD。
后来新增的工作文件保留为 untracked；新文件、目录或 symlink 阻挡原路径恢复时，在写入前拒绝并保留记录。
原本没有 index 的命名对象仓库可录制冲突；abort 恢复 index 不存在，保留一切工作文件。
未命名 legacy 历史必须先建立有明确路径的 index，程序不猜路径。单目标 skip 做同样的恢复后结束本次操作。
quit 只清除本地记录，允许处理外部引用更新后已陈旧的操作，不回退其他人的新提交。

已有 pending 时，普通 commit/amend、新历史操作、整树 reset、分支切换、绑定分支 rename/delete 和 stash push/apply/pop 会拒绝。
add/rm/mv/restore/路径 reset 继续用于准备结果；status 显示绑定及 conflict/prepared/published 状态。
pending 存在而 index 损坏时，status 明确给出 index_error 和不可用字段，不把未知状态当 clean。

## 发布与恢复

续作先完整验证、准备并安装对象闭包，再持久化 prepared 提交 ID 与所用 index 原始摘要，然后才发布引用、reflog，最后清除状态。
引用发布前重试必须仍是同一分支、原 HEAD 和同一份有效 index；不会用后来修改的 index 偷换已准备的提交。
若引用已经指向 prepared 提交，重试从实际提交树重新审计、补缺本 generation 的唯一 reflog 并清理，既不重复提交也不重复记 log。
这一恢复即使当前 index 被移除或损坏也可完成；不会覆盖后来修改的工作内容。
第三种 HEAD 或同 tip 的另一分支会被拒绝，不自动 reset。

固定测试构造发布前与发布后中断状态，以及缺失 reflog、恢复失败和陈旧 generation，验证上述恢复分支；不是随机杀进程或断电测试。
多文件恢复不承诺断电时整体回滚：中途 I/O 失败保留 pending，并准确报告可能已完成的恢复、发布或清理步骤。
`.uwgit/pending.json` 为本地规范 version 1 JSON，包含原 index 备份的编码总量限制为 64 MiB。
重复键、非规范编码、未知字段、非法绑定、非普通文件和 symlink 明确拒绝；pending 不进入对象、bundle、clone、HTTP 或 SSH 的仓库状态。

这些命令与 Git 的控制语义作过对照。后续已加入[索引 stages](index-stages.md)、[多目标 replay](replay-queue.md)、[线性 rebase 续作](rebase-pending.md)和 [HEAD 状态](head-and-pathspec.md)。交互式 rebase 与全部 Git 选项仍未完成。
参考 [Git merge](https://git-scm.com/docs/git-merge)、[Git cherry-pick](https://git-scm.com/docs/git-cherry-pick)、[Git revert](https://git-scm.com/docs/git-revert)、[Git rebase](https://git-scm.com/docs/git-rebase)；准确命令边界仍见[能力矩阵](git-command-coverage.md)。
