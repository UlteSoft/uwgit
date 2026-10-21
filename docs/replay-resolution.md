# 快进约束与单父手工重放

参见 [Git 命令能力盘点](git-command-coverage.md)。本接口为 merge／pull 增加显式快进约束，
并为 cherry-pick／revert 提供审定完整 index 后发布单父提交的接口。
对象、提交及网络传输格式不变；Core Wasm 原始字节的保存规则不变。

## 快进约束

`merge DIR REV --ff-only [-m MESSAGE]` 允许未出生分支采用已有历史、快进到后代，及已经包含目标的无操作。
两个方向均没有祖先关系时明确失败；即使文件内容可自动合并，也不创建合并提交。
拒绝分叉发生在求共同祖先、自动合并和安装新对象之前。完整对象存储验证、分支名与旧 tip 的 CAS、
已有 index／工作区的干净要求及 untracked 保护继续适用。

`pull DIR [REMOTE] [BRANCH] --ff-only [-m MESSAGE]` 先 fetch，再以同一约束整合目标。
若整合失败，fetch 导入的对象和 remote tracking 可以保留，但本地分支、index 和工作文件不应改变。
默认远端分支选择见 [upstream](upstream.md)。
快进模式不产生新提交，因此允许省略消息；普通 merge／pull 仍保留原来的必需消息参数。
`--ff-only` 与手工解决参数组合时拒绝，重复或无效选项也不静默忽略。

祖先语义参考 [Git merge](https://git-scm.com/docs/git-merge) 和 [Git pull](https://git-scm.com/docs/git-pull)。

## 审定完整暂存结果

```sh
wasm-git cherry-pick DIR TARGET_FULL_ID --resolved-index \
  --expect-head REVIEWED_HEAD_ID --expect-branch main -m 'reviewed replay'
wasm-git revert DIR TARGET_FULL_ID --resolved-index \
  --expect-head REVIEWED_HEAD_ID --expect-branch main -m 'reviewed reversal'
```

TARGET 和预期 HEAD 必须为完整的 64 位小写十六进制提交 ID。
root 目标不接受 `--mainline`；单父目标默认选父 1；合并提交须以 `--mainline N` 明确选定范围内的父提交，
含义参考 [Git cherry-pick](https://git-scm.com/docs/git-cherry-pick) 和 [Git revert](https://git-scm.com/docs/git-revert)；
本程序的 `-m` 仍用于提交消息。

这个入口保存用户完整审定的真实 index，包括新增、删除和空树。必须自行准备整个结果树，
包括需要保留的非冲突变更；它不自动补入目标的其他修改，不要求此前执行过失败的自动重放。
发布的父列表严格只有审定的当前 HEAD；目标提交和选定 mainline 以审计报告绑定，不作为第二父提交。
报告将手工结果与自动成功区分，提供原始字节及文件内审计证据。

该操作只发布对象与本地引用，不重写 index 或工作文件，允许保留未暂存修改。
缺失 index 不等于空 index。旧历史的文件映射必须有明确且一致的 legacy anchor。
所有逻辑校验在安装对象前完成，最终发布仍验证分支和旧 tip；I/O 失败按实际完成范围报告，
不承诺跨文件断电事务。

持久冲突续作见 [单目标续作](pending.md) 与 [rebase 续作](rebase-pending.md)；默认远端选择见 [upstream](upstream.md)。
