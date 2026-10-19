# 2026-10-19 第二轮：官方 Core 语料与大型差异定位

本轮在原 SSH Linux 容器/cgroup 中运行，仍为 64 GiB、swap=0；没有在本机编译或执行测试。
最终 `fmt/clippy/tests/spec` 状态均为 0，全部源码及测试工具摘要与当前 checkout 核对一致。

## 本轮实现

- 大型差异回退使用唯一且逐字节核对的 32 字节内容窗口，支持插入/删除后的偏移定位。
  全局与局部 Myers 共享最多 8,000,000 个搜索工作单位；回退不宣称全局最小。
- 新增公共 `wasm_git::audit` 库接口，CLI 与语料验证使用同一实现。
- 修复 import 身份碰撞：`("a:b","c")` 与 `("a","b:c")` 使用结构化元组编码得到不同 ID。
- 官方语料下载校验 archive SHA-256，测试后逐个复核实际读取的文件集合及文件 SHA-256。
  同时记录模块摘要、位置、解析/验证状态、恒等 diff 和字节突变重放结果。

## 回归结果

| 检查 | 结果 |
|---|---|
| `cargo fmt --check` | 通过 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 |
| 库单元测试 | 18 通过 |
| CLI 内部单元测试 | 67 通过 |
| 原 CLI 集成测试，含实际 C→Wasm 编译/链接 | 17 通过 |
| Core 特性集成测试，含 import 身份碰撞 | 15 通过 |
| 历史/未知指令集成测试 | 2 通过 |
| WAST 兼容适配自测 | 3 通过 |
| 常规测试合计 | **122 通过，0 失败** |
| 外部语料测试 | **3 个版本分别通过审计检查** |

常规 `cargo test` 中，外部语料测试显式 ignored；本轮另用 `--ignored` 在三个固定语料上逐一执行。
该检查不实例化 wasm，不执行 invoke、assert_return、trap 等 runtime 断言。

## 官方固定语料

完整 pin 见 `tools/spec-corpora.json`。这些是固定 tag 快照，不宣称包含上游之后新增的测试。

| Core | 官方 tag 与 commit | WAST 文件 | 模块案例 | 可审计二进制模块 |
|---|---|---:|---:|---:|
| 1.0 | [wg-1.0 / 977f970](https://github.com/WebAssembly/spec/tree/977f97014c962f7bd1291fcc6d28b41a924882bf/test/core) | 73 | 2,957 | 2,500 |
| 2.0 | [wg-2.0 / fffc6e1](https://github.com/WebAssembly/spec/tree/fffc6e12fa454e475455a7b58d3b5dc343980c10/test/core) | 148 | 5,672 | 4,563 |
| 3.0 | [wg-3.0 / 9d36019](https://github.com/WebAssembly/spec/tree/9d36019973201a19f9c9ebb0f10828b2fe2374aa/test/core) | 258 | 7,132 | 5,878 |
| 合计 | 全部递归 `.wast` 文件 | **479** | **15,761** | **12,941** |

12,941 个二进制模块均完成恒等比较和一次确定性变更的精确编辑重放。
另有 2,736 个畸形文本案例在生成二进制前按预期拒绝，84 个错误文件头按预期拒绝。
文件集合复核无遗漏、无 symlink 排除、无 Component Model 排除。

不同版本 baseline profile 拒绝、但当前全部已知 feature 接受的扩展案例分别为 26、21、8 个，
报告为 `baseline_rejected_known_extension_accepted`。这与工具允许额外 feature 的范围一致。

## 历史规则差异与适配范围

Core1 的旧测试脚本包含现代 WAST parser 不再支持的 NaN runtime 断言，以及旧 active data/elem
selector 写法。测试适配器按 token/AST 处理，保存原始源码摘要与每一项适配记录。
旧 NaN runtime 断言没有执行；移除其解析占位不会改动相邻模块原始位置。
合法 Unicode 名称通过 lexer 明确启用后解析；quoted text 也使用相同策略。

**存在一条已披露的历史验证差异，不能计作验证器一致性通过。**
[Core1 `unreached-invalid.wast:538`](https://github.com/WebAssembly/spec/blob/977f97014c962f7bd1291fcc6d28b41a924882bf/test/core/unreached-invalid.wast#L538)
要求 unreachable 后的 `br_table` 各目标标签类型一致；当前 wasmparser 的分支操作数校验规则接受该模块。
`WasmFeatures::WASM1` 只切换 feature，不恢复所有历史 typing 规则。
此项以源文件 SHA-256 与编码后模块 SHA-256 双重限定，独立记录在 `known_profile_limitations`。
其他未预期的 baseline 验证差异仍使测试失败。

该模块仍被完整定位，恒等 diff 和变更重放均通过。报告保留原始 `assert_invalid` 期望和实际接受结果，
不会把它描述为 Core1 validator-conformance 成功，也不据此声称运行时语义符合官方测试。

## 证据和复跑

```sh
UWGIT_RUN_SPEC=1 tools/test-linux.sh
```

远端最终证据：`/tmp/uwgit-20261019/evidence`。
本机原始副本：`/tmp/uwgit-20261019-r2-evidence`；源码、构建、语料及日志均在 `/tmp`。
包括 `spec-inputs.json`、三个版本的逐模块完整 JSON、`spec-verification.json`、完整测试日志及源码摘要。
历史失败运行保留在远端 `evidence-*` 目录中。

最终源码清单包含 Cargo 文件、全部 Rust 源码/测试、fixtures 和全部 tools 文件；其 SHA-256 为：

```text
f76530ac2322c87a528381b41183b5a31330b8c3c801646d15cf70fb8b4ddfc5
```

原 cgroup 与 boot id 同[首轮记录](testing.md)。最终运行前后 `memory.events` 计数全部为 0；
共享 `memory.current` 为 53,020,692,480 / 53,180,534,784 字节，不能解读成本任务峰值。
