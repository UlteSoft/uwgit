# uwgit

基于纯 WebAssembly Core 二进制的审计与去中心化版本历史。当前命令名为 `wasm-git`。
Wasm 1.0–3.0 的二进制头版本均为 1；本工具不通过文件头推断语言特性版本。
所有宿主接口统一作为 import/export 记录，不依赖宿主协议。Component Model 不在范围内。

原始文件是事实来源：不通过 WAT 往返转换，不丢弃 custom section，不把规范化结果作为存储对象。
函数匹配用于解释对应关系；完整字节审计决定是否发生变化。

## 比较与定位

```sh
wasm-git inspect module.wasm --json
wasm-git diff old.wasm new.wasm
wasm-git diff old.wasm new.wasm --format json
wasm-git diff old.wasm new.wasm --short
```

JSON 的 `audit` 包含全部物理 section、已解码条目/函数/局部变量/指令及其原始文件偏移。
`edits` 提供旧/新文件的半开区间 `[start,end)`、精确十六进制字节与两侧上下文；
这些编辑可逐项应用于旧文件，完整重建新文件。编码形式不同但含义相同的 LEB、NaN 位模式、
重复条目的数量、section 顺序和未知内容都参与比较。

已知标准 section 1–13 都做结构化解码，包括 GC 递归类型组、引用类型、异常 tag、
`try_table`/catch/throw，以及 memory、global、element、data 和初始化表达式。
指令特性由固定版本 `wasmparser` 的操作码表标注，包括已知的额外提案。
`validation` 与解码结果分开报告：读懂字节不等于模块满足类型及结构验证。

未知指令会标出 opcode 起始偏移，保留其所在表达式/函数剩余内容，不猜测后续指令长度；
有长度边界的后续函数和 section 仍可审计。未知 section 也保留并标注。
无法解码的已知标准内容明确报告错误，不冒充已解释的内容。
标准向量的后项损坏时，保留此前完整条目的说明和位置；失败项起到 section 末尾作为未解码区间。
import 不完整时，后续函数只报告 defined index，不猜测全局 function index。
`function_analysis.available=false` 时，完整字节审计仍然返回结果。

目前结构化识别 `name`、`producers`、`target_features` 三种 custom 约定。
仅在整个内容满足严格识别规则（长度、规范 LEB、唯一/顺序约束、完整消耗）时解释；
同名但格式不符、格式扩展或其余 custom section 都作为不透明数据保留与定位。
这是一种保守识别策略，不能把 custom 约定解码失败解释成 Core 模块无效。

最小编辑采用 byte insertion/deletion 距离。有界 Myers 成功时 `exact_minimal=true`；
达到工作量或距离上限会明确设置 `false`，使用唯一、逐字节核对的内容窗口定位插入/删除后的局部差异。
所有局部搜索共享预算；无法进一步对齐的间隙仍保留完整且可重放的差异。
函数/指令的对应关系与全局最小字节脚本是不同的结论。
这里的精确位置是二进制文件位置；缺少调试信息时不能据此恢复原始源代码行。

## 离线补丁

```sh
wasm-git patch old.wasm new.wasm --output change.uwgp
wasm-git apply old.wasm change.uwgp --check
wasm-git apply old.wasm change.uwgp --output restored.wasm
```

补丁绑定前后完整原始文件的 SHA-256，逐项校验区间、旧字节和重放后摘要，成功后才发布完整输出文件。
未知或不透明内容同样精确重放；`--check` 返回重新计算的审计结果。
支持 `--repo` 从同一仓库快照读取 revision，返回实际提交 ID；不自动提交或修改引用。
格式与限制见[补丁说明](docs/patch.md)。

## 区间历史

```sh
wasm-git trace ./history HEAD --path 'code[0]/function[0]'
wasm-git trace ./history HEAD --range 40:48
```

从固定提交的原始字节区间沿全部父边查询相关变更，输出两侧物理位置、原始字节、上下文和影响范围。
重复内容的对齐不构成唯一来源证明；替换、插入、删除边界及多父合并分别保留证据。
遇到对齐回退或预算边界时返回 `complete=false` 和未继续查询的 frontier。
查询规则与限制见[历史追踪说明](docs/trace.md)。

## 分布式历史

```sh
wasm-git init ./history
wasm-git commit ./history old.wasm -m 'initial module'
wasm-git clone ./history ./peer
wasm-git branch ./peer work
wasm-git switch ./peer work
wasm-git commit ./peer new.wasm -m 'update function'
wasm-git bundle ./peer peer.uwgb
wasm-git unbundle ./history peer.uwgb incoming
wasm-git diff main incoming --repo ./history --format json
wasm-git merge-base ./history main incoming
wasm-git merge ./history incoming -m 'combine independent changes'
wasm-git log ./history HEAD
wasm-git checkout ./history HEAD restored.wasm
wasm-git fsck ./history
```

每个仓库保存自己的 SHA-256 对象库、提交 DAG、分支和 HEAD，可独立提交及离线交换；不需要中心服务。
提交保存完整原始 wasm 字节。clone 保留所有分支；unbundle 只更新明确指定的接收分支，
已有分支只允许快进。checkout 的目标必须不存在，防止覆盖文件。
导入前校验全部对象摘要、对象类型和父链闭包；`fsck` 同样检查未引用对象。
对象通过临时文件和原子发布写入，引用更新有仓库锁。
仓库版 `diff` 的两侧引用在同一已验证快照中解析，报告同时记录实际提交 ID。
checkout、bundle 和补丁输出通过不覆盖目标的原子发布创建完整新文件。

提供保守三方合并：独立函数及受限的完整指令修改可自动组合，冲突输出三侧物理位置与原始字节，
不写入部分结果。手工解决保留双父历史，并以预期 HEAD 和不可变目标 ID 防止使用过期解决文件。
具体范围、退出码及用法见[合并说明](docs/merge.md)。

尚未提供网络传输协议、签名、压缩 pack 或垃圾回收；自动合并也不证明行为符合开发者意图。
摘要用于内容完整性，不证明作者身份；本地拥有写权限的人仍可重写引用或删除整个仓库。
崩溃遗留的 `.uwgit/write.lock` 需确认没有写进程后手动移除。
完整性检查和 bundle 当前需要将对象载入内存，尚未针对超大仓库做性能承诺。

## 验证

开发测试在 SSH Linux 的既有 cgroup 内运行；本机测试产物只能放在 `/tmp`。
可复用 [Linux 测试脚本](tools/test-linux.sh)，它只进入指定的现有容器，不创建或修改 cgroup。
设置 `UWGIT_RUN_SPEC=1 tools/test-linux.sh` 会额外下载并校验固定的官方 Core 1.0/2.0/3.0 语料，
递归处理其中的 `.wast` 文件并生成逐文件/模块审计记录。该测试不执行 wasm 或 runtime 断言。
固定依赖使用 `Cargo.lock`；测试包括有效 Core 特性样本、逐字节编辑重放、未知/畸形内容、
custom 识别回退，以及 clone/分支/bundle/fsck 的端到端流程。

设计依据、对象格式和已知边界见 [设计文档](docs/design.md)。
最新结果为 226 项回归测试通过，其中区间追踪还包含 1,922 次短数据查询覆盖检查；
固定官方语料 479 个文件的审计检查也通过。
12,941 个二进制模块还完成了共 25,882 次序列化补丁重放。
历史查询覆盖、Core1 历史验证差异和环境证据见[第五轮验证记录](docs/testing-round5.md)。
搭配真实 `uwvm2-ros/examples` 的验证可运行 `tools/test-uwvm-examples.sh`；
默认只读取相邻的 `../uwvm2-ros`，也可用 `UWGIT_UWVM_SOURCE` 指定参考仓库。
该脚本在现有 Linux cgroup 中编译和测试，核对参考输入前后摘要，不修改参考仓库。
347 个原始 Wasm、347 个 WAT 产物及 7 个真实 C/C++ 编译产物均通过 WABT/uwvm 双验证；
另有 6 项版本管理流程及 14 次 preload 实际运行。覆盖范围、固定工具及复跑要求见
[真实示例验证记录](docs/testing-uwvm-examples.md)。
此前结果保留在[首轮](docs/testing.md)、[第二轮](docs/testing-round2.md)、
[第三轮](docs/testing-round3.md)和[第四轮](docs/testing-round4.md)记录。
