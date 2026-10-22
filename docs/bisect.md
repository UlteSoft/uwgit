# 不切换工作区的历史二分

`bisect` 用于根据用户提供的 good/bad 判断定位历史变化，参照 [Git bisect](https://git-scm.com/docs/git-bisect) 的 no-checkout 工作流。本程序只实现下列子集，不执行测试脚本，不从 Wasm 内容自动推断判断，也不宣称覆盖 Git 的全部选项。

```sh
wasm-git bisect DIR start [--no-checkout] [--first-parent] BAD GOOD...
wasm-git bisect DIR good [REV...]
wasm-git bisect DIR bad [REV]
wasm-git bisect DIR skip [REV...]
wasm-git bisect DIR status
wasm-git bisect DIR next
wasm-git bisect DIR log
wasm-git bisect DIR reset
```

所有模式均不切换 HEAD，不改 index、pending 或工作文件。start 的 no-checkout 是默认行为，也可显式给出。结果为 JSON；状态查询给出候选的完整提交 ID，可再交给 `show`、`inspect --repo` 或 `archive` 审阅原字节，使用者自行测试后再标记。省略 REV 时标记持有本次 writer 锁时的当前候选，而不是当前 HEAD；自动化应显式传入实际测试过的完整 ID，避免其他操作者推进候选后误用省略形式。

开始必须提供一个 bad 和至少一个 good，所有初始 good 都必须是 bad 的祖先；first-parent 模式只沿第一父链判断祖先。不为不同历史的初始端点执行 Git 的额外 merge-base 探测。已有会话时 start 明确拒绝覆盖，需先审阅并 reset。修订在一次已验证快照中解析为完整 ID，之后引用重命名、移动或工作分支推进不会替换原来的判断。

## 候选与跳过

设当前已知 bad 为 B，所有已知 good 为 G，A 表示所选父链策略下包含自身的祖先集合。剩余嫌疑集合为：

```text
P = A(B) \ union(A(g) for g in G)
T = P \ (skipped union {B})
weight(c) = |A(c) intersect P|
score(c) = min(weight(c), |P| - weight(c))
```

从可测试集合 T 中选择 score 最大的提交，平分时按完整对象 ID 的 ASCII 顺序选择。权重始终以完整 P 为基础；skip 只表示无法测试，不会偷偷当成 good 或 bad。

只有 P 恰剩 B 时才报告找到首个 bad。若仍有多个嫌疑而 T 为空，报告跳过造成的歧义，列出全部嫌疑，不猜测唯一结果。这些结论建立在用户判断正确且所追踪性质沿所选历史具有单调变化的假设上；未测试的模块不获得运行时正确性保证。

JSON 的 `status` 区分 `testing`、`found`、`ambiguous_skipped`、`inactive` 和 `reset`。这些可报告状态均退出 0；参数、对象或会话验证失败退出 1。与 Git 在仅剩跳过项时的退出码不同，自动化必须读取 status，不能把退出 0 解释为已经找到唯一结果。

活动报告的 remaining 与 suspects 均为完整 P，testable 为 T，三者都是完整 ID 数组而非计数；candidate 仅在 testing 时存在，first_bad 仅在 found 时存在。generation 是本次会话固定的 64 字符十六进制标识，不是步数；marks 保存有序的有效判断批次，重复已成立判断可保持幂等而不增加事件。

后续 bad 必须沿当前 bad 的祖先链收缩，不能跳到另一条不相祖先的坏分支。good 可来自初始历史域内的其他分支，但不能把当前已知 bad 的后代标成 good。批量标记须整体验证成功再发布，矛盾、域外或无法解析的提交不留下部分判断；已跳过提交可在实际测试后明确标为 good/bad。

## 本地状态与边界

会话仅是 `.uwgit/bisect.json` 本地辅助元数据，冻结完整 ID 和有序判断；读取时根据已验证对象图重算候选，不相信存储的派生答案。状态采用版本化的规范 JSON 加单个 LF，拒绝重复或未知字段、无效 ID、非规范排列、矛盾或冗余事件；文件最多 1 MiB、标记事件最多 4,096 个，读取与发布均检查界限。

会话不进入 commit、bundle、clone 或远端广告，也不改变原有对象格式。status、next、log 不发布会话修改。除 reset 外，操作都使用一次 writer 锁中的完整已验证对象快照，不读取 index、pending 或工作文件；不相关的脏状态不影响已提交历史。reset 只移除常规会话文件并同步目录，可清理损坏 JSON，不读取或认证对象，因此报告 `object_verification: not_requested`；其他操作报告完整快照验证。链接、目录及其他特殊会话文件明确拒绝，不作为待清理常规文件处理。

现有 count-objects 仍按引用、tracking 与 reflog 端点统计可达性，不把本地 bisect 会话列为额外 root；unreachable 不是允许删除的证明，显式 GC 的保守恢复 root 策略见[维护契约](native-commands.md)。

start/mark 的原子发布与 reset 的目录同步沿用仓库已有边界：发布、删除或结果写出后的 I/O 错误可能发生在元数据已改变之后，应先查询实际会话再重试。不会为了恢复会话而修改历史、暂存或工作字节。已跳过的事件保留在日志中；报告的 skip 只列当前范围内仍未分类的跳过项，不把已被后续判断排除的项目继续算作未知。

不支持自动 checkout、reset 到另一个修订、任意命令 run、shell 日志 replay、自定义 terms、路径筛选和 skip 范围简写。需要这些形式时会明确失败，不能把当前实现视为完整 Git bisect。
