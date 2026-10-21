# checkout 与路径恢复

参见 [Git 命令能力盘点](git-command-coverage.md)。本接口补齐 checkout 的常用显式入口，并修正未匹配路径无操作成功的问题。
对象、提交和传输协议不变；模块仍保存完整原始 Core Wasm 字节，不按当前标准配置丢弃未知内容。

## 实现

- `checkout DIR BRANCH`、`checkout DIR -b NAME [REV]` 复用 switch 的工作区锁、分支检查和预检。
- `checkout DIR -- PATH...` 从 index 恢复工作路径，index 和 HEAD 不变。
- `checkout DIR REV -- PATH...` 从不可变修订读取所选路径，更新 index 与工作文件，HEAD 不变。
- `checkout DIR REV NEW_FILE [--file PATH]` 保留旧的独占导出。恢复已有路径必须有真正的 `--`；导出目标本身名为 `--` 时写 `./--` 或绝对路径。
- restore、checkout 路径模式与 reset 路径模式共用选择器，支持精确文件、目录前缀、`.`／`./`，及单次开头 `./`。
  单个末尾 `/` 只选择目录后代。每个显式参数必须匹配；任一未匹配、非法路径或空的显式分隔符选择都在写入前拒绝。
- `reset DIR [REV] -- PATH...` 仅恢复所选 index，保留 HEAD、工作文件和其他暂存项。不能与整树 reset 模式组合；首个提交前的默认 HEAD 路径 reset 明确报错。

checkout 的修订路径模式遵循 [Git checkout 的 overlay 规则](https://git-scm.com/docs/git-checkout)：
保留 source 没有的无关路径，同时允许所选源路径替换有前缀冲突的受控文件／目录。
restore 新增 `--overlay`，默认仍为 [Git restore 的 no-overlay 规则](https://git-scm.com/docs/git-restore)，
从 index／source 并集选择，可恢复源树删除。精确模块导出的 `--file` 不按目录选择器展开。

文件／目录替换只移除与所选源路径有严格前缀冲突的受控项；已有 untracked、非空无关子目录、符号链接与元数据路径保护继续有效。
所有路径完成匹配、目标树校验和工作区预检之后，才开始发布。I/O 失败仍报告实际完成范围，不承诺跨文件断电事务。

`--` 必须先排除单值选项的字面操作数：例如旧导出 `--file --` 的末尾是文件名值，
而 `checkout DIR -- --file` 的末尾是工作路径。真正分隔符后的帮助或导出标志均按字面路径处理；真正帮助仍在仓库 I/O 前返回。

没有增加 detached/orphan HEAD、upstream、冲突 sequencer 或隐式路径猜测。
分支模式继续要求已建立的 index/worktree 干净；没有 index 的对象仓库不会因为切换分支自动物化工作文件。
