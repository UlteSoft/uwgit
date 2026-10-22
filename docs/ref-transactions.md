# 原生引用事务

`update-ref` 只发布 uwgit 已验证的实际 commit；Wasm、tree、commit 和 SHA-256 对象格式保持原样。单引用入口与批量入口使用同一套持久化事务。显式 HEAD 操作可以改变当前工作树的指针，index 和工作文件始终保持原字节；需要切换工作文件时使用 switch。

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

普通引用使用 `refs/heads/NAME` 和 `refs/tags/NAME`；HEAD 的附加规则见下节。NEW/OLD 可以使用受支持的 commit 修订语法，全部在准备时的同一个已验证快照中解析。前一行排队的新值不会改变后一行修订的含义。64 个零或文本中的 `""` 表示零值；零 NEW 的 update 删除普通引用，零 OLD 要求旧 oid 不存在。create 要求不存在且 NEW 非零；delete 的显式 OLD 不能为零；verify 省略 OLD 时要求旧 oid 不存在。

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

每条记录/字段最多 8192 字节，每个事务最多 4096 个引用；持久记录最多 64 MiB。`--no-deref` 及逐条 `option no-deref` 选择 HEAD 本身；普通分支和标签本来就是直接引用。`--deref` 恢复默认，命令行相反开关以后一个为准，逐条 option 只作用于下一条引用指令。不将文件系统符号链接解释成引用。`--create-reflog` 可用，原生模型本来就为所有实际引用变更记录日志。同值 update 和 verify 不追加日志。

默认在准备时同时检查所有旧值、目标 commit 类型及完整对象图、引用名称和最终文件/目录前缀冲突、当前及其他已注册 worktree 的分支占用。任意一项不成立时，整批都不发布。删除 `topic` 并创建 `topic/child`，或相反，可以在同一事务完成；删除的分支同时清理其 upstream 关联。

## 原生 HEAD 的符号引用事务

```sh
wasm-git update-ref DIR --stdin --no-deref -m 'attach reviewed HEAD' <<EOF
start
create refs/heads/reviewed EXISTING_COMMIT_ID
symref-update HEAD refs/heads/reviewed ref refs/heads/main
prepare
commit
EOF
wasm-git update-ref DIR --stdin --no-deref <<EOF
symref-verify HEAD refs/heads/reviewed
EOF
wasm-git update-ref DIR --no-deref HEAD EXISTING_COMMIT_ID EXPECTED_OLD_COMMIT_ID
```

`symref-update HEAD NEW_TARGET [ref OLD_TARGET | oid OLD_ID]` 和 `symref-verify HEAD [OLD_TARGET]` 接入同一事务。目标仅为正常 `refs/heads/NAME`；可指向尚无提交的 unborn 分支。ref 租约要求 HEAD 确实是所给符号目标，detached HEAD 失败；oid 租约比较当前真实 tip，也可将 detached HEAD 按预期 oid 重新附着。没有 tip 时用 64 个零检查。verify 省略目标要求符号引用不存在，uwgit 正常仓库的 HEAD 因而会拒绝这一条件。

这两条符号指令要求全局 `--no-deref` 或前一条 `option no-deref`。同一事务可创建或更新目标分支，再一次性发布 HEAD；oid 修订仍从事务准备时的原快照解析，HEAD 完成日志使用最终目标分支的实际 tip。默认普通 HEAD update 仍保护已检出分支；显式 `--no-deref` 的普通 update 将 HEAD 切到真实 commit，进入 detached 状态。原生 HEAD 必须存在，删除 HEAD 和任意符号别名的创建/删除仍不在当前模型中。

NUL 输入为 `symref-update SP HEAD NUL TARGET NUL MODE NUL OLD NUL`，不提供旧值时 MODE 和 OLD 均为空字段；MODE 只能为 ref 或 oid。`symref-verify SP HEAD NUL OLD_TARGET NUL` 的空字段表示未提供目标。HEAD 与其默认解引用分支不能在同一批次重复指定；`--no-deref` 操作 HEAD 本身时，可与普通分支更新并列。HEAD 的 JSON 报告明确区分 symbolic/commit 身份及实际 old_commit/new_commit，不把分支名当作提交 ID。

单独 `symbolic-ref HEAD TARGET` 也使用相同事务。HEAD 身份真正变化时，共享日志和该工作树自己的 HEAD 日志各记一次；prepare、abort、EOF 丢弃和同身份操作不追加。`checkouts.json` 保持原样，因为这些入口只修改指针。索引、Wasm 工作副本和其他工作树的 HEAD 日志不变。

包含 HEAD 的事务使用 journal version 2，记录 origin 的已注册 worktree ID（primary 使用空 ID）、HEAD 原/新身份、原始 worktree 注册和本地 HEAD 日志。仅更新普通引用的 version 1 编码保持兼容。恢复目标从注册 ID 或 primary 的实际目录解析，journal 不能直接指定任意输出路径。恢复前同时核对 HEAD、注册、两个日志及全部引用的原/新像；linked worktree 打开时先完成持久事务恢复，再核对注册一致性，允许修复两次写入之间的合法中断。任何第三种人工编辑都先失败保持。

## 逐项拒绝模式

`--stdin --batch-updates`（或 `--stdin -0`）将可解析请求中的语义失败逐项拒绝，其余项继续作为一笔原生事务发布。`--no-batch-updates` 恢复默认整批检查；两种开关同时出现时，以后一个为准。

```sh
wasm-git update-ref DIR --stdin --batch-updates <<EOF
create refs/tags/reviewed EXISTING_COMMIT_ID
update refs/heads/topic NEW_ID STALE_OLD_ID
EOF
```

在 topic 的旧值不匹配时，reviewed 标签仍可创建；对应拒绝记录使用 `rejected REF NEW OLD REASON` 的逐行文本，未提供的值写为 64 个零。NEW/OLD 是同快照解析后的真实对象 ID，拒绝行按完整引用名排序，`-z` 仍输出换行文本。省略 OLD 的 verify 仍要求不存在，不会变成任意值校验。拒绝项没有引用、upstream 或 reflog 写入；同值 update 与 verify 成功项也不追加日志。全部项被拒绝时，处理仍成功退出且不发布事务记录或日志。

可逐项拒绝的情形包括旧值不匹配、要求不存在但已存在、要求旧提交却不存在、完整 ID 指向缺失或非 commit 对象、最终名称前缀冲突，以及 uwgit 的已检出分支保护。已有引用保持其可接受的更新；两个互相冲突的新引用同时拒绝，不依赖输入先后。先过滤失败的删除条件，再检查名称结构；被拒绝的删除不能为另一项创建腾出名称。

错误字段数、重复引用、非法名称、未知修订表达式、create 的零 NEW、delete 的显式零 OLD、不完整 NUL/文本记录、未知命令与选项仍是整批错误。无法读取或损坏的对象、日志、worktree 注册等元数据，以及锁或 I/O 错误也不会变成逐项拒绝。所有准备检查完成后才写入持久决定；提交后的 I/O 失败沿用下述恢复规则，不能解释为已经回滚。

prepare 保存接受项及其拒绝结果，并持有共享锁，不输出拒绝行；只有 commit 完成后才输出拒绝行，随后输出 `commit: ok`。abort 或未提交的 EOF 丢弃整笔事务，包括未发布的拒绝结果。隐式 EOF 提交则在完成后输出拒绝行。后续新的 start 独立处理下一笔事务。

## 锁、提交和恢复

没有 start 或 prepare 的输入在 EOF 隐式提交；使用 start 或 prepare 后必须 commit，否则 EOF 丢弃当前事务。start 也可将此前已排队的更新纳入显式事务。prepare 验证快照后持有共享 writer 锁，响应 `prepare: ok` 后不会提前发布。abort 或 EOF 释放这个锁，不写入持久提交决定。commit/abort 后可用新的 start 开始下一笔事务；已经提交的前一笔不因后来一笔失败而撤销。各控制响应立即 flush，可用于交互管道。

commit 先同步 `.uwgit/ref-transaction.json`，保存完整引用前像、逐项旧/新值、原始 upstream 和 reflog 字节。该记录是持久提交决定：随后顺序写入配置、引用和完整日志，最后同步删除记录。返回 I/O 错误时会明确说明提交可能已经发生，不能把错误当作回滚。

每次获取共享 writer 锁后，查询和写入都会先检查这份记录。恢复使用保存的前像验证完整对象库和其他元数据，再一次性预检所有当前引用、upstream 和 reflog：只能是各项原像或目标像。随后幂等补齐最终结果和固定日志字节，避免重复追加。若有后来人工写入的第三种内容，整次恢复先失败，保留内容和记录，所有后续受锁操作也停止。应检查并恢复对应原像/目标像，再重试查询。进程崩溃遗留的 writer 锁仍沿用现有规则，需要人工检查并移除；不会根据 PID 猜测并自动解锁。

一致性面向遵守共享锁的 uwgit 读写操作。直接读取底层多个引用文件的外部程序可能观察到安装中间态；旧版本也不识别新恢复记录，不应在恢复未完成时混用。

## 验证及范围

回归覆盖混合更新/创建/删除/校验、旧值失败整批保持、同快照修订解析、NUL 与 C 引号、交互 prepare 的真实锁、EOF/abort、跨 worktree 保护、两向前缀替换和多笔事务。恢复测试在配置、删除、引用写入及 reflog 每个检查点中断，再从普通查询恢复，并验证引用、upstream 和日志原字节；完整安装后再次恢复也只保留一次日志。损坏记录、重复项、缺失对象和第三种人工编辑必须失败保持。

HEAD 测试覆盖主/linked worktree 从任一入口打开恢复、符号与 detached 两向格式转换、第三种规范编码注册/HEAD/日志内容的失败保持、旧 journal 兼容及 stale writer 锁的人工处理。24 组独立 Git 对照检查 ref/oid 租约、detached/unborn、NUL 和指针操作后的引用值及原字节。

逐项模式另覆盖成功/拒绝混合、全拒绝保持、只为接受项记日志、原生分支保护、选项覆盖、交互拒绝输出时机，以及过滤后的接受子集逐写入前缀恢复。独立 Git 仓库对照语义拒绝、名称冲突、prepare/abort/EOF/commit、NUL、格式错误及最终引用值；Wasm 原字节、index 和工作树也必须保持。

协议语义参考 [Git update-ref](https://git-scm.com/docs/git-update-ref)，实际实现和恢复记录均为 uwgit 原生。本轮仍不包含任意符号别名及 `symref-create/delete`、任意引用命名空间、网络多引用原子推送；这些仍在能力矩阵中列为剩余项。
