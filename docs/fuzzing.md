# 原始字节审计 fuzz

常规 `cargo test` 包含确定性的逐位翻转、插入/删除及文件头拒绝测试。
`UWGIT_RUN_FUZZ=1 tools/test-linux.sh` 另执行长程确定性变异，输出逐例 JSONL；
其输入、变异、原始摘要及覆盖位置由 `check-audit-fuzz.py` 独立核对。

`tools/test-fuzz-linux.sh` 增加 LLVM libFuzzer 与 AddressSanitizer 的覆盖率引导测试。
它只在 SSH `linux` 的既有容器/cgroup 内编译和执行，源码副本、种子、发现语料及所有产物均写入远端 `/tmp`。
本机只打包、传输和保存 `/tmp` 证据，不运行 fuzz binary。

```sh
UWGIT_LIBFUZZER_RUNS=20000 tools/test-fuzz-linux.sh
```

入口要求同一远端任务目录已有固定 `nightly-2026-10-18` minimal 工具链与
`cargo-fuzz 0.13.2`，位置分别为任务的 `toolchain/{cargo,rustup}` 和 `fuzz-tools/bin`。
工具不会切换默认 Rust 工具链，不创建或修改 cgroup。
主包和 fuzz 包各自保留 Cargo.lock；编译和种子生成均使用锁定依赖。

## 输入与性质

`raw_audit` 的输入上限为 4096 字节：前两个字节组成 little-endian selector，
其余 payload 用 `selector % (payload.len()+1)` 分成两侧，各自添加固定的八字节 Core header。
不足两个字节的输入代表两个空 payload。这样 mutation 不会因为损坏 magic 而绝大多数提前退出，
同时可到达任意两侧小型 payload、空模块、恒等、插入/删除和互不相关的原文。
它不要求 payload、section、类型、指令或模块合法。
固定文件头的性质边界与八字节文件头变异拒绝测试分开。

每次执行检查：

- 四配置的完整物理拓扑、描述、原始 ByteEdit 相同。
- section frame 覆盖全部原始 payload；所有区域、上下文、诊断及特性证据范围均有界，证据 hex 等于输入原文。
- 已报告编辑之间的所有字节确实相同，独立读取编辑 hex 后完整重建目标；不同原文不能返回 unchanged。
- 两个方向的补丁均经过序列化/重新读取和精确重放。
- 第二个补丁 producer 手工构造 whole-file replacement，绕过 `patch::create` 与共享 diff 实现，再校验重放。
- 两侧总长度不超过 128 时，用独立二次动态规划计算 insertion/deletion 距离；
  当审计声明 `exact_minimal=true`，要求总编辑成本等于该距离，不要求存在唯一对齐。

四配置一致不单独证明标准分类正确；标准正确性由官方语料预期、手工原始编码及回归矩阵另行检查。
所有性质都不执行 Wasm guest。

## 种子、覆盖反馈与证据

`fuzz/generate_seeds.rs` 生成固定 WAT 和 literal hex 种子，覆盖 Core 1/2/3 特性、已知额外提案、
未知 section/opcode、非法类型、断裂 framing 与表达式。每个模块产生恒等、append custom、
插入和删除的输入对；manifest 保存 envelope 和两侧原始字节摘要。
WAT 只用于生成部分输入，literal 不经过文本归一化。

runner 固定 libFuzzer seed、有限执行次数、最大输入、单例 timeout 和 RSS 上限，
保存完整 argv、编译器版本/摘要、源码清单、初始化与结束的 cov/ft、全部发现语料及 crash artifacts。
成功后，用同一 ASan binary 再执行全部保留语料。
`check-libfuzzer.py` 复核种子确实对应声明的两侧字节、输入和二进制摘要、全部阶段状态、
实际执行数、SanitizerCoverage counter/PC table、NEW 与覆盖反馈增长、完整语料重放及空 crash 目录。
失败时保留输入、日志及阶段状态，不把未完成或异常退出算作通过。

libFuzzer 的 cov/ft 是搜索反馈指标，不等于规范条款或分支的完整覆盖百分比。
有限时长、输入上限和 ASan 检查也不构成任意未来文件的数学完备证明。

实现方法参考官方 [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html)、
[cargo-fuzz setup](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html) 与
[LLVM libFuzzer 文档](https://llvm.org/docs/LibFuzzer.html)。
