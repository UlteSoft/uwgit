# 2026-10-19：搭配 uwvm2-ros 真实示例验证

本轮新增外部示例测试及独立证据校验工具，没有修改 `uwvm2-ros`。
全部编译、测试、Wasm 验证和 guest 执行均在 SSH `linux` 的既有 cgroup 中进行。
本机只读取、打包、校验参考输入，并在 `/tmp` 保存传输文件和证据副本。

## 参考输入与结果

参考仓库：`/Users/liyinan/Documents/MacroModel/src/uwvm2-ros`。
固定 HEAD：`6eb8dd2d0ca51f93cf3df63b9f7316728ee60afe`。
收集全部 `examples` 普通文件 720 个及实际编译需要的 SDK 头文件 5 个，
记录相对路径、长度和 SHA-256；拒绝符号链接及非普通文件。
原仓库所选输入的 Git 状态及全部 725 个文件的摘要在运行前后相同。
远端使用这些文件的副本，编译和变更实验写入独立目录。
这里通过只读访问及前后校验保护参考输入，没有使用 OS 强制只读挂载。

| 检查 | 结果 |
|---|---:|
| `fmt` / `clippy --locked --all-targets -- -D warnings` | 通过 |
| 常规回归 | 226 通过，0 失败 |
| 全部原始 `.wasm` | 347 个 |
| 全部 `.wat` 的新编译产物 | 347 个 |
| 对应 WAT/原始 Wasm 的精确差异及补丁重放 | 343 对 |
| 恒等、确定性字节变更及上述配对的序列化补丁重放 | 1,731 次 |
| 真实 ROS1/ROS2 C/C++ guest 编译 | 6 个 |
| 真实 C 源码受控变更编译 | 1 个 |
| WABT 与 uwvm 独立验证 | 701 个全部通过，无分歧 |
| 版本管理端到端场景 | 6 项全部通过 |
| 这 6 项中的外部命令 | 379 次 |
| preload 实际执行 | 14 次：10 次成功，4 次预期失败 |

694 个示例二进制分别检查完整解码、验证状态、独立 import/export/type 清单，
并从恒等和字节变更审计结果重建目标文件，再序列化/反序列化补丁并重放。
字节变更样本用于验证完整记录和重放，不要求每个受损变体仍是合法 Wasm。
343 对中有 342 对原始字节与新编译结果不同；测试不假设编译工具及调试信息产生相同编码。

## 真实版本变更与执行见证

主要使用 `examples/0004.preload_wasm/{main,lib}.wat`，仅在测试目录中生成变体。
独立编译器、`wasmparser`、WABT 反汇编、`sha256sum` 以及实际 uwvm 执行分别提供核对依据。
测试不以 uwgit 自己的审计输出作为唯一正确性依据。

| 场景 | 具体检查 |
|---|---|
| 函数常量 | main 的期望 argc 从 3 改为 4；原版本成功，变体断言 trap；检查指令位置、完整字节和补丁 |
| import/export | 修改预加载库名和导出函数名；旧绑定失败，正确绑定成功；核对 module/name 字符串与索引 |
| 函数索引移动 | 插入未使用 import 并同步 call/start 索引，执行结果保持；并发函数修改触发合并冲突，仓库完整不变 |
| name 与不透明内容 | 只修改函数名字，独立核对非 custom 字节相同，两版本执行成功；畸形 name 回退、未知 opcode 定位及精确重放 |
| 真实三方合并 | 两分支分别让 `get_argc` 加 1、argv 字节数加 2；合并产物逐字节等于独立编译的组合源码，双父对象及全父历史通过核对 |
| 现有 tail-call 示例对 | `proxy_caller` 与 `proxy_tail` 的真实输入检查 `call` 到 `return_call` 的变化及版本管理流程 |

合并执行测试使用期望 argc=4、argv 字节数=18 的 main：独立组合产物和 uwgit 合并产物都执行成功，
未修改库按预期 trap。流程还检查双父提交的原始对象封装、摘要和父 ID。
各场景覆盖提交、checkout、clone、离线 bundle/unbundle、`fsck`、区间历史及补丁重放；
恢复结果直接比较原始字节和独立 SHA-256。
未知 opcode 只做静态拒绝、标注与原始字节保留检查，没有执行该无效变体。

## 真实 C/C++ 与最小物理位置

复制 `examples/ros1` 和 `examples/ros2` 下的 `talker.c`、`listener.c`、`talker.cpp`，
配合所需 SDK 头文件，使用 clang 22 编译成纯 `wasm32-unknown-unknown` guest。
保留编译命令、依赖及输入摘要。WABT 独立枚举的 imports 与 uwgit 结果完全一致，
只含对应 ROS namespace 和 WASI 字符串，没有意外的 `env` 辅助导入。
uwgit 对这些接口仍按普通 Core import/export 处理。

另把 ROS1 `talker.c` 的 `1000000000ULL` 改成 `1000000001ULL` 后独立编译。
WABT 反汇编确认一处 `i64.const` 变化，uwgit 定位为：

```text
code[0]/function[4]/operator[30]
指令区间 [883,889)
值 1000000000 -> 1000000001
指令内实际字节变化 [884,885): 80 -> 81
```

调试 custom 内容的其他差异也由完整字节审计保留，不把上述单字节误称为整个文件的唯一变化。
补丁恢复文件与独立编译变体逐字节相同。该案例没有运行 ROS 或验证实际等待时间。

## 环境、复跑与证据

从 uwgit 仓库运行：

```sh
tools/test-uwvm-examples.sh
# 参考仓库位于其他位置时：
UWGIT_UWVM_SOURCE=/absolute/path/to/uwvm2-ros tools/test-uwvm-examples.sh
```

脚本复用 SSH `linux` 的 `uwvm-debug-core3-v48-20261011` 容器，不创建或修改 cgroup。
远端要求已有 `/tmp/uwgit-20261019` 工具链、clang/WABT 和以下固定 uwvm 产品，
缺失时失败，不回退到本机执行。环境路径见 `tools/test-uwvm-examples-remote.sh`。

```text
cgroup /system.slice/docker-4dd58ad4560fde2ab9b539e4ef9cab1fac531654e99ad554aff1fce8ae0eae37.scope
boot id 51c27aa1-d709-4a06-ba16-2ac3003fbcbd
memory.max 68719476736; memory.swap.max 0; CPU 0-31
Rust/Cargo 1.99.1; Python 3.14.4; clang 22.1.8; WABT 1.0.36
uwvm 2.0.4.0 [ROS], LLVM AOT
uwvm SHA-256 a43f92c52fc7f201027dbe84db0ad95c5a4580d980b35c8d1f034a6f0d745be1
```

运行产品来源：
`/tmp/uwvm-pretty-20261018/products-r819-all3-O2-wset-r821-r1/uwvm2-ros/uwvm`。
每轮先核对摘要，再复制到独立目录执行；运行前后复核原产品、动态库和编译工具摘要。
全部子进程继承并留在上述 cgroup；运行前后 `memory.events` 各项均为 0。

最终证据路径与源码清单摘要在完成最后一次复跑后记录于此。
报告包括逐文件 corpus、6 项流程的完整命令/状态/输出摘要、701 个双验证结果、
真实编译输入及产物、全部参考输入前后校验，以及独立汇总校验结果。

本轮证明所测输入的审计、字节重放、版本交换和合并流程有效，并有 preload 执行见证。
没有启动 ROS 网络、网关或机器人，也没有执行宿主侧 native 插件加载场景。
WABT 1.0.36 在这些输入上通过不构成全部 Core 3.0 特性的通用认证。
官方 Core 语料的既有验证及差异披露见[第五轮记录](testing-round5.md)。
