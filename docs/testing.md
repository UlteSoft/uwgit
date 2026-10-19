# 2026-10-19 Linux 验证记录

本轮在 `ssh linux` 上既有的 `uwvm-debug-core3-v48-20261011` 容器进入原 cgroup，
通过容器中的 `/host` 根目录运行工具链。未新建或改动 cgroup；本机未编译或运行测试。
工具链、构建目录、测试临时文件及原始日志均位于 `/tmp`。

## 结果

| 检查 | 结果 |
|---|---|
| `cargo fmt --check` | 通过 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 |
| 单元测试 | 80 通过，0 失败 |
| 原有 CLI 测试 | 17 通过，0 失败 |
| Core 特性 CLI 测试 | 14 通过，0 失败 |
| 去中心化历史及未知指令 CLI 测试 | 2 通过，0 失败 |
| 合计 | **113 通过，0 失败，0 ignored** |

C 集成测试实际使用 LLVM Clang 22 编译两份 C，使用 Rust 工具链自带 LLD 链接为 wasm，
再执行 inspect/diff 断言。本轮设置显式 `WASM_GIT_CC`，编译或链接失败直接使测试失败，不允许跳过。
此前发现系统 Clang 寻找 `wasm-ld-22` 而非无后缀名字，已在任务的 `/tmp/bin` 中配置转发脚本。

14 个特性测试在 CLI 调用之前分别编码并验证两侧有效样本，覆盖普通控制流、任意宿主命名空间与五类 import、
GC rec/struct/array/字段变化、typed function reference/call_ref、externref/typed select、
try_table/catch/throw/tag、SIMD lane、NaN payload、memory64/多内存、atomic、
memory.init/table.init 目标索引、标准 section 1–13 及纯函数名称变化。
每个样本还将报告的字节编辑应用于旧模块，检查与新模块逐字节一致。
这批样本不是官方完整 spec suite；其中线程/atomic 等额外提案也依固定版本解码。

单元回归包含小规模二元字母表全部输入上的最短编辑距离与重放验证、逐个 payload 字节突变、
大距离明确回退、32,768 条指令的区间查询复杂度、未知指令/section、畸形 custom 回退、
控制字符显示、重复函数歧义、重复条目数量、对象与父链篡改、离线交换及非快进拒绝。
CFG/调用图只提供 approximate/incomplete 的模型元数据，不能作为行为等价或安全证明。

## 环境与证据

- cgroup：`/system.slice/docker-4dd58ad4560fde2ab9b539e4ef9cab1fac531654e99ad554aff1fce8ae0eae37.scope`
- `memory.max=68719476736`，`memory.swap.max=0`，实际进程归属在测试脚本内核对。
- boot id：`51c27aa1-d709-4a06-ba16-2ac3003fbcbd`。
- rustc：`1.99.1 (58cf8f9c3 2026-10-13)`；cargo：`1.99.1 (5f94df478 2026-08-27)`。
- 最终运行前后 `memory.events` 的 high/max/oom/oom_kill 等计数全部为 0。
- 共享 cgroup 的 memory.current 前后为 59,585,847,296 / 59,612,798,976 字节；这是共享用量，不是本任务峰值。

远端证据目录为 `/tmp/uwgit-20261019/evidence`；本机副本为 `/tmp/uwgit-20261019-evidence`。
包含完整 tests/fmt/clippy 日志、环境、内存事件、status.json 和源码 SHA-256 清单。
最终源码清单（Cargo 文件、全部 Rust 源码/测试及 wasm/C fixtures）与当前 checkout 逐项核对一致。
清单本身的 SHA-256 为：

```text
b56cc3806c235b634473de344bf8b06b5a7e720089eb94943dd2447989a79322
```

复跑命令为仓库内 `tools/test-linux.sh`。默认复用上述容器和 `/tmp/uwgit-20261019/toolchain`；
可以设置 `UWGIT_SSH_HOST`、`UWGIT_CONTAINER`、`UWGIT_REMOTE_ROOT`。
远端目录须预先安装 Rust/rustfmt/clippy，脚本不会在系统目录安装软件。
最终运行的原始状态是 `{"fmt":0,"clippy":0,"tests":0}`。
修复期间的前次失败日志保留在远端同级 `evidence-*` 目录，最终结果不将其计为通过。
