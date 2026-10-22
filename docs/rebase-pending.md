# 线性 rebase 持久队列与冲突续作

线性 rebase 支持显式录制持久队列。默认 rebase 仍是无状态全量计算，晚冲突不会建立 pending 或发布中间提交。接口参照 [Git rebase 官方手册](https://git-scm.com/docs/git-rebase)的 continue/skip/abort/quit；本程序在冲突期间保持原分支与 HEAD，进度保存在本地对象及 journal，和 Git 的中间 detached HEAD 有明确差异。

## 使用与结果范围

```sh
wasm-git rebase DIR UPSTREAM [--onto NEW_BASE] --record-conflict
wasm-git rebase DIR --continue --resolved-index
wasm-git rebase DIR --skip
wasm-git rebase DIR --abort
wasm-git rebase DIR --quit
```

开始时要求已有受控 index/worktree 干净；无 index 的命名对象仓库也可用，但不自动物化工作区。upstream、onto、唯一 merge base 及从原 tip 到 base 的完整单父队列均冻结为完整 ID，后续引用移动不能替换队列。根提交和 merge commit 不作为 replay source，未知选项、重复或混用 control、新 target/onto 与 continue/skip 的组合均明确拒绝。

continue 审定当前停止步骤的**完整暂存树**，不会自动补入当前步骤其他非冲突路径。该步骤的 base 为原提交父树，ours 为当前已重放进度，theirs 为原提交树。接受后自动重放后续步骤，到下一冲突返回退出 2，到队列结束才一次发布原分支。每次新的停止都须重新审阅并显式使用 --resolved-index。

skip 不读取 index，只跳过当前原提交，再继续余下步骤；和单目标 pick/revert 的 skip 恢复原 baseline 后结束不同。continue/skip 保留当前 index 与工作文件，最终 tip 可能包含后续自动步骤；物化最终树须保存当前编辑后显式 restore。全自动开始成功时则沿用正常干净历史工作区同步，并在发布前检查 untracked/目录阻挡，逻辑拒绝不写对象、journal 或引用。

abort 恢复开始时的原始 index 编码及原受控工作文件，保留后来新增文件；恢复阻挡时先拒绝。原本无 index 时恢复其不存在并保留工作文件。quit 只删除本地记录，不发布中间进度，也不回退其他 writer 的新引用。继续和 abort 绑定原分支/HEAD，陈旧操作只能显式 quit。已有 pending 的 commit/amend、切分支、新历史、整树 reset 和 stash 应用等保护继续生效。

## 状态、审计与中断恢复

pending version 1 新增可省略的 rebase 子记录，旧单目标记录的原编码继续可读。队列、cursor、progress tip、各步原 source/before/result/action、手工 raw index SHA 和 prepared action 均受 64 MiB 编码总量限制。每次读取严格核对原队列与源父链，逐步重放自动步骤并比对其实际树；历史 manual/skip 也必须对应当时实际冲突，不接受把自动干净步骤伪写成手工解决或跳过的规范 JSON。

每个 manual result 都从存储的不可变四侧重建原 bytes/hex/SHA、精确审计和差异。报告保留所有步骤的 old/new 映射及 skipped 列表，第二次冲突的 ours 使用第一步实际结果，而非仍未变化的公开 HEAD。

重放对象闭包安装完成后才发布 journal；最终 prepared tip 持久化后才移动引用并记录同 generation 的 reflog。continue 准备的最终结果在引用发布前要求同一份有效 raw index 和最后一次手工树一致，后续自动步骤可以改变最终树；begin/skip 不使用 index，其 prepared 恢复也不要求 index。引用已指向 prepared 时可在 index 缺失或损坏后修复缺失 reflog 并清理，不重复提交或 log。恢复不自动同步工作文件。

这些是固定构造的中断状态与 I/O 边界检查，不是随机杀进程或断电测试。多文件工作区 I/O 失败不保证整体回滚，错误明确指出可能完成的步骤。pending 不进入对象格式、bundle 或 HTTP/SSH 状态；完整对象包可能包含已安装的未引用进度对象，不能把“状态不传输”解释成“这些对象绝不传输”。

此 rebase 接口尚不支持 interactive/todo 编辑、merge 拓扑保留、root replay、patch-equivalence 自动去重或自动生成冲突 stages。通用[索引 stages](index-stages.md)、[HEAD 状态](head-and-pathspec.md)和[多目标 pick/revert](replay-queue.md)已由其他接口提供。准确能力见[命令矩阵](git-command-coverage.md)。
