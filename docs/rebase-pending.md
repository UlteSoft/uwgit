# 线性 rebase、自动 stages 与恢复检查点

`rebase --record-conflict` 在已有 index 的工作区中使用 version 3 原生队列。
每个停止步骤自动提供完整 stage 0 和真实冲突原侧，continue/skip 同步当前结果，整个队列完成后才一次发布原 HEAD。
普通 rebase 仍为 stateless 全量计算：晚冲突不发布半成品，不建立记录。

```sh
wasm-git rebase DIR UPSTREAM [--onto NEW_BASE] --record-conflict
wasm-git ls-files DIR --unmerged
# 编辑并 add/rm，审阅当前步骤的整个暂存树
wasm-git rebase DIR --continue --resolved-index
wasm-git rebase DIR --skip
wasm-git rebase DIR --abort
wasm-git rebase DIR --quit
```

## 冻结来源与步骤

开始时受控 index/worktree 必须干净；原来的 skip-worktree 缺席可以保留。
在已验证快照内绑定原 HEAD、完整 upstream/onto ID、唯一 merge base 和原单父序列。
源队列不含 root 或 merge commit；后续引用改变不能更换队列或目的地。空队列直接使用实际 onto，不制造合成提交。
原 HEAD 一直保留，进度是实际原生单父提交；不模仿 Git 的中间 detached HEAD 或虚构作者/时间。

每一步的 base 是原 source 的父树，ours 是当前重放进度，theirs 是原 source 树。
支持的非冲突 Wasm 组合和路径增删进入 stage 0，未解决项保存真实 stage 1/2/3，工作侧保留 ours。
以后步骤尚未重放的文件不会提前混进当前结果。用户不必先 restore progress 或重建其他非冲突路径。

continue 要求 `--resolved-index`、完整已解决 index 和没有意向条目。
该完整树只替换当前停止步骤，用户选择的删除不会自动补回；其后自动重放直到下一停止或完成。
不受结果影响的脏编辑保留；会被后续自动步骤覆盖时，在任何对象、journal 或文件发布前拒绝。
skip 丢弃当前来源的解决内容并继续，保留无关新文件和无关编辑，可以用已验证的进度重建损坏 index。
所有步骤成功时，检查点同步最终 index 和工作文件，然后发布 tip。报告含 queue/cursor/progress、各步 source/before/result/action 和实际更新标志。

abort 恢复最初 index 的原编码、原受控字节及缺席，删除本次已物化并归属操作的路径，保留无关用户文件。
quit 只忘记状态。两者仍保护目录/symlink/类型阻挡；第三种 HEAD 或同 tip 的另一检出分支拒绝 continue/skip/abort，陈旧状态可 quit。
控制不能组合新 upstream、onto、消息或其他替换选项；准备期间的普通历史写入继续受 guard 保护。

## 日志、审计和中断

`replay.rebase` 保存 upstream/onto/fork_base，`replay.queue` 保存冻结 source，所有内容与原 index/工作域一起绑定摘要。
每次读取重新计算原队列和每个自动步骤，核对父链、实际 Wasm 树和消息，拒绝伪造 fork、source 顺序或对象类型。
每个手工结果从存储对象重建四侧 bytes/hex/SHA 与审计，位于 `manual_resolutions`；后续冲突的 ours 使用真实进度。

Wasm→tree→父先于子提交的闭包安装后才保存物化检查点。逐文件及 index 完成并结算后，才发布最终引用与唯一 generation reflog。
任一物化中断保留原/新字节；重试不重复制造提交，不覆盖后来的第三种编辑。
修复到冲突停止时不会消费未经审定的 index。最终引用已发布而 reflog/清理未完成时，继续可保留后来编辑的 index/工作区并补 log。
这不是跨文件断电原子事务；固定测试构造各写入前缀、引用已发布缺 log、状态篡改及迟到编辑。

旧 version 1 rebase 记录继续可读，原有 prepared 手工 index 摘要约束及元数据续作保持有效。
无 index 的命名对象仓库继续选用这种模式，不自动建立或物化工作区；continue 要自行准备完整树，skip 不替换其当前 index/工作文件。
该兼容模式完成后可显式 restore。原本无 index 的 abort 恢复其不存在并保留工作字节。

验证包括 [rebase_pending_cli.rs](../tests/rebase_pending_cli.rs)、[恢复测试](../src/repository_sequencer.rs) 和独立 [Git 对照](../tests/git_reference_cli.rs)。
interactive/todo、保留 merge 拓扑、root replay、自动 patch-equivalence 及其他 Git 选项仍见[能力矩阵](git-command-coverage.md)。
