# 测试指南

## 常规回归

测试入口为 `tools/test-linux.sh`。脚本通过 SSH 在既有 Linux 容器/cgroup 中编译和执行，将源码快照、构建目录和日志写入远端 `/tmp`。

```sh
UWGIT_SKIP_FUZZ=1 UWGIT_RUN_DOCTEST=1 tools/test-linux.sh
```

可用 `UWGIT_SSH_HOST`、`UWGIT_CONTAINER`、`UWGIT_REMOTE_ROOT` 选择环境。
远端任务目录须预先提供 `toolchain/cargo` 与 `toolchain/rustup`，包含 Rust、rustfmt 和 Clippy；脚本不会安装工具链或创建容器。
脚本核验既有 cgroup 的内存、swap、CPU 和资源事件。环境不满足要求时直接失败。
常规阶段执行格式检查、Clippy、SDK 输入检查、Rust 单元与 CLI 回归；C 集成使用明确配置的 LLVM/LLD。
`UWGIT_SKIP_FUZZ=1` 排除变异目标及指定的穷举属性测试；`UWGIT_RUN_DOCTEST=1` 增加文档测试。

## 官方语料和真实示例

```sh
UWGIT_SKIP_FUZZ=1 UWGIT_RUN_SPEC=1 tools/test-linux.sh
UWGIT_SKIP_FUZZ=1 tools/test-uwvm-examples.sh
```

官方语料通过固定版本及摘要校验，逐例审计和结果核对由 `tools/fetch-spec-corpus.py`、`tools/check-spec-reports.py` 与 `tools/check-spec-inputs.py` 完成。
真实示例默认从相邻的 `uwvm2-ros` 读取，可用 `UWGIT_UWVM_SOURCE` 指定参考仓库；输入快照、产物重放及 guest 验收由对应脚本核验。
跳过 fuzz 时，语料使用 `originals-only` 模式，不构造变异。

## Fuzz 与测试产物

确定性变异与 LLVM libFuzzer 的入口、依赖和核验方式见 [fuzz 指南](fuzzing.md)。这些阶段须显式选择。
日志、receipt、语料、编译产物和分轮结果保存在任务目录，不提交到仓库。保留的回归代码、fixtures、执行工具和依赖补丁用于复现行为。
成功结果只适用于当次源码和输入快照；完整性摘要、有限语料或 fuzz 覆盖反馈不证明任意输入上的行为正确。
