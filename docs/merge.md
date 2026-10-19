# 三方合并与冲突处理

uwgit 使用提交 DAG 中的共同祖先作为 base，比较当前 HEAD（ours）与目标提交（theirs）。
共同祖先的“最佳”关系按[Git merge-base 的定义](https://git-scm.com/docs/git-merge-base)计算：
若一个共同祖先是另一个共同祖先的祖先，前者不是最佳候选。
当前只自动处理唯一最佳共同祖先；无共同祖先或多个最佳共同祖先时拒绝猜测。

```sh
wasm-git merge-base ./history main incoming
wasm-git merge ./history incoming -m 'combine independent function changes'
```

`merge` 返回 JSON；成功为退出码 0，内容冲突为退出码 2，输入或仓库错误为退出码 1。
状态区分 `fast_forward`、`already_up_to_date`、`merged` 和 `conflict`。
快进更新当前分支；已包含目标的历史不产生新提交；非快进合并生成父提交顺序为 `[ours,theirs]` 的提交。

## 自动合并范围

整体字节相同或只有一侧相对 base 变化时，直接保留所选一侧的完整原始字节。
这包括当前无法解码的 feature 字节，不经 WAT 重编码。

对于两侧都变化的模块，自动组合依赖严格的边界条件：

- section 布局必须可一一对应。布局增删或重排不通过位置猜测身份。
- type/import/function/table/memory/global/element/data/datacount/tag 等上下文变化会阻止并行自动组合，
  防止索引重新绑定被当作局部独立修改。
- code 函数数量必须一致。不同函数的单侧变化可直接选择原始函数体，保留其指令、局部变量和编码形式。
- 同一函数只有在局部变量编码、指令数量和结构化控制流骨架保持一致时，才逐条组合完整指令。
  call、branch 和 exception 控制指令要求原始字节不变，含未建模 stack-switching 控制的函数拒绝并行组合。
  同一指令被两侧不同修改时冲突，立即数的不同字节不被拆成两次独立编辑。
- 可识别的函数体搬移及指令搬移会阻止并行自动组合；旧位置内容消失、在另一修改位置重新出现时，
  不凭相同数量和签名将其当作普通就地编辑。函数体检测要求与 base 中唯一完整 payload 的字节相同，
  指令检测比较发生变化位置之间的完整原始指令字节。base 中重复的函数体不参与唯一性检测，
  未变化的指令副本不会触发判断；修改过的搬移及编码不同的等价搬移也无法靠这项检查完整识别。
- 无法完整解码的并行函数修改保持冲突；未知内容不会被猜测成可拼接的指令。
- 可对应的 custom section 按整个 section 处理，不把不透明 payload 内的不同字节解释成独立字段。

新组合的模块必须通过当前全部已知 feature 的验证。即使两个输入分别有效，组合后栈类型不一致，
也会返回冲突而非保存无效结果。这是结构化合并检查，不能证明组合后的程序行为符合开发者意图。

只在组合后必要时修正包围内容的长度字段，尽可能保留原来的 LEB 编码宽度，修正记录在 `framing_fixups`。
可直接选择的完整字节片段不因合并而规范化。生成的模块仍可使用普通 `diff` 逐字节审计。

## 冲突与手工解决

冲突 JSON 的 `report.conflicts` 提供 path、原因，以及 base/ours/theirs 三侧的原始区间和十六进制字节。
报告中的 `old_head`、`target`、`base` 为实际使用的提交 ID。
发生冲突不会保存部分模块、修改分支或写入新对象，也不建立隐藏的 pending-merge 状态。

准备完整的解决结果后，用冲突报告中的 ID 明确绑定所处理的双方：

```sh
wasm-git merge ./history THEIRS_COMMIT_ID -m 'resolve conflict' \
  --resolved resolved.wasm --expect-head OURS_COMMIT_ID
```

手工路径要求目标是完整不可变提交 ID，且当前 HEAD 必须仍为 `--expect-head`。
HEAD 已前移就拒绝写入，避免用旧冲突结果覆盖协作期间的新修改。
它仍要求双方历史分叉并有唯一共同祖先；不适用时明确拒绝，不忽略提供的解决文件。

成功状态为 `merged_resolved`，提交保存解决文件的精确原始字节与两个父提交。
返回 JSON 中的 `manual_resolution` 标注文件由调用者提供，并包含当前解析器的验证结果与诊断数量；
调用者可保存该 JSON 作为操作证据。此标注和验证快照不持久化到提交对象，后续 `show`/`log` 不返回它们。
手工路径要求 Core 文件头，允许未知特性或无效函数体作为明确选择保存，不能将其冒充自动合并证明。

## 仓库写入与恢复

读取引用、校验对象及完整父链、选 base、产生结果和发布引用在同一仓库写锁中完成。
保存完整 blob 和 commit 后才原子更新分支。冲突和期望 HEAD 不匹配发生在写对象之前。
I/O 中断可能遗留可由 fsck 发现的未引用对象；引用发布前不会指向尚未完整写入的对象。

合并后的双父 DAG 可继续 clone、bundle/unbundle、fsck 和 log。
此版本不实现 Git 的递归虚拟 base、跨布局索引重编号、语义等价证明或自动行为冲突解决。
