# 原生引用事务

`update-ref` 只发布 uwgit 已验证的实际 commit；Wasm、tree、commit 和 SHA-256 对象格式保持原样。单引用入口与批量入口使用同一套持久化事务。HEAD、index 和工作文件不会被这个命令物化或切换。

```sh
wasm-git update-ref DIR refs/heads/topic NEW_ID EXPECTED_OLD_ID
wasm-git update-ref DIR -d refs/tags/obsolete EXPECTED_OLD_ID
wasm-git update-ref DIR --stdin -m 'publish reviewed references' <<EOF
start
update refs/heads/topic NEW_ID EXPECTED_OLD_ID
create refs/tags/release NEW_ID
delete refs/tags/obsolete EXPECTED_OLD_ID
verify refs/heads/main REVIEWED_MAIN_ID
prepare
commit
EOF
```

## 输入与检查

文本输入逐行接受 `update REF NEW [OLD]`、`create REF NEW`、`delete REF [OLD]`、`verify REF [OLD]`，以及 `start`、`prepare`、`commit`、`abort`。字段可使用 C 字符串引号和三位八进制转义。空行、错误字段数、同一事务内重复引用、无效 UTF-8、不完整记录和未知命令都会失败。

引用限于 `refs/heads/NAME` 和 `refs/tags/NAME`。NEW/OLD 可以使用受支持的 commit 修订语法，全部在准备时的同一个已验证快照中解析。前一行排队的新值不会改变后一行修订的含义。64 个零或文本中的 `""` 表示零值；零 NEW 的 update 删除引用，零 OLD 要求引用不存在。create 要求不存在且 NEW 非零；delete 的显式 OLD 不能为零；verify 省略 OLD 时要求不存在。

`-z` 使用以下 NUL 字段，省略的 OLD 也必须提供一个空字段。空 OLD 表示没有提供该条件；verify 仍检查不存在。create 没有 OLD 字段。控制命令的响应总是逐行文本。

```text
update SP REF NUL NEW NUL OLD NUL
create SP REF NUL NEW NUL
delete SP REF NUL OLD NUL
verify SP REF NUL OLD NUL
start NUL
prepare NUL
commit NUL
abort NUL
```

每条记录/字段最多 8192 字节，每个事务最多 4096 个引用；持久记录最多 64 MiB。`--no-deref` 及逐条 `option no-deref` 适用于这里的直接引用；不将文件系统符号链接解释成引用。`--create-reflog` 可用，原生模型本来就为所有实际引用变更记录日志。同值 update 和 verify 不追加日志。

准备时同时检查所有旧值、目标 commit 类型及完整对象图、引用名称和最终文件/目录前缀冲突、当前及其他已注册 worktree 的分支占用。任意一项不成立时，整批都不发布。删除 `topic` 并创建 `topic/child`，或相反，可以在同一事务完成；删除的分支同时清理其 upstream 关联。

## 锁、提交和恢复

没有 start 的输入在 EOF 隐式提交；显式 start 后必须 commit，否则 EOF 丢弃当前事务。prepare 验证快照后持有共享 writer 锁，响应 `prepare: ok` 后不会提前发布。abort 或 EOF 释放这个锁，不写入持久提交决定。commit/abort 后可用新的 start 开始下一笔事务；已经提交的前一笔不因后来一笔失败而撤销。各控制响应立即 flush，可用于交互管道。

commit 先同步 `.uwgit/ref-transaction.json`，保存完整引用前像、逐项旧/新值、原始 upstream 和 reflog 字节。该记录是持久提交决定：随后顺序写入配置、引用和完整日志，最后同步删除记录。返回 I/O 错误时会明确说明提交可能已经发生，不能把错误当作回滚。

每次获取共享 writer 锁后，查询和写入都会先检查这份记录。恢复使用保存的前像验证完整对象库和其他元数据，再一次性预检所有当前引用、upstream 和 reflog：只能是各项原像或目标像。随后幂等补齐最终结果和固定日志字节，避免重复追加。若有后来人工写入的第三种内容，整次恢复先失败，保留内容和记录，所有后续受锁操作也停止。应检查并恢复对应原像/目标像，再重试查询。进程崩溃遗留的 writer 锁仍沿用现有规则，需要人工检查并移除；不会根据 PID 猜测并自动解锁。

一致性面向遵守共享锁的 uwgit 读写操作。直接读取底层多个引用文件的外部程序可能观察到安装中间态；旧版本也不识别新恢复记录，不应在恢复未完成时混用。

## 验证及范围

回归覆盖混合更新/创建/删除/校验、旧值失败整批保持、同快照修订解析、NUL 与 C 引号、交互 prepare 的真实锁、EOF/abort、跨 worktree 保护、两向前缀替换和多笔事务。恢复测试在配置、删除、引用写入及 reflog 每个检查点中断，再从普通查询恢复，并验证引用、upstream 和日志原字节；完整安装后再次恢复也只保留一次日志。损坏记录、重复项、缺失对象和第三种人工编辑必须失败保持。

协议语义参考 [Git update-ref](https://git-scm.com/docs/git-update-ref)，实际实现和恢复记录均为 uwgit 原生。本轮不包含 HEAD 或其他符号引用的批量 `symref-*`、`--batch-updates` 的逐项拒绝模式、任意引用命名空间及网络多引用原子推送；这些仍在能力矩阵中列为剩余项。
