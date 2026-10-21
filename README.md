# uwgit

基于纯 WebAssembly Core 二进制的审计与去中心化版本历史。当前命令名为 `wasm-git`。
Wasm 1.0–3.0 的二进制头版本均为 1；本工具不通过文件头推断语言特性版本。
所有宿主接口统一作为 import/export 记录，不依赖宿主协议。Component Model 不在范围内。

原始文件是事实来源：不通过 WAT 往返转换，不丢弃 custom section，不把规范化结果作为存储对象。
函数匹配用于解释对应关系；完整字节审计决定是否发生变化。

函数引用会结合解析目标比较：同一个 `call 0` 可能因 import 换序而改绑，
不同数值索引也可能仍指向同一候选。`call_bindings` 给出逐位置的目标、签名与匹配依据，
覆盖 `call`、`return_call`、`ref.func`；递归或重复目标的身份不确定性会明确保留。

## 比较与定位

```sh
wasm-git inspect module.wasm --json
wasm-git inspect module.wasm --standard core1 --json
wasm-git diff old.wasm new.wasm
wasm-git diff old.wasm new.wasm --standard core3 --format json
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

`inspect`、`diff`、`apply` 可选 `--standard core1|core2|core3|all-known`，默认 `all-known`。
标准配置独立判断每个节、类型、编码形式与指令的要求；已识别但禁用的内容以 binary 视图标注，
仍完整读取已知立即数，保留后续受支持指令的位置。非法编码、非法语义和真正未知的扩展分别报告。
配置不改变原始 ByteEdit 或补丁结果。使用方法与未知指令的恢复边界见[标准配置](docs/standards.md)。

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

提供暂存区、状态、撤销、stash、标签、reflog、线性历史重放和 HTTP/SSH remote/server。
暂存提交支持多模块文件树，新增、删除、改名和空树均进入版本历史：

```sh
wasm-git add ./history modules/a.wasm modules/b.wasm
wasm-git commit ./history -m 'track module tree'
wasm-git inspect HEAD --repo ./history --json
wasm-git diff main incoming --repo ./history --format json
wasm-git show ./history HEAD --file modules/a.wasm --output exported.wasm
wasm-git trace ./history HEAD --file modules/a.wasm --range 40:48
```

文件树 inspect/diff 默认列出所有路径；`--file` 选择单个模块用于解释、导出或补丁。
新增和删除保留完整单侧字节证据，改名明确表示为删除加新增，不猜历史身份。
旧单模块对象、提交 ID 和读取方式保持兼容，升级时显式记录旧内容对应的路径。
整树手工合并可用 `merge --resolved-index --expect-head OURS_ID` 提交完整暂存结果，
绑定不可变的另一父提交，并报告 base、ours、theirs、resolved 四侧原始证据；不改写暂存区或脏工作区。
文件与目录可相互转换，写入前检查整组路径，拒绝覆盖未跟踪内容。
日常命令与工作区规则见[类 Git 工作流](docs/git-workflows.md)，
部署、认证、引用租约及传输格式见[HTTP 与 SSH 服务](docs/server.md)。
与 Git 常用命令的已支持、部分支持和缺失项见[命令能力矩阵](docs/git-command-coverage.md)；checkout 提供分支、显式路径恢复和兼容的独占导出入口。
本轮路径匹配、overlay 与路径 reset 的实现边界及最终结果见[checkout 与路径恢复验证](docs/checkout-paths.md)。
merge／pull 另支持 `--ff-only`；cherry-pick／revert 可用 `--resolved-index --expect-head ID`
提交用户审定的完整暂存树，保持单父历史和未暂存工作字节，详见[快进约束与单父手工重放](docs/replay-resolution.md)。
分支 upstream 支持设置、取消、`-vv` 与 `@{u}` 查询，并接入默认 pull/push；网络 clone、分支及 remote 的 rename/delete 同步维护关联，详见[upstream 验证与范围](docs/upstream.md)。
merge/cherry-pick/revert 可用 `--record-conflict` 录制单目标冲突，再用 `--continue --resolved-index`、`--abort` 或 `--quit`；pick/revert 另支持单目标 `--skip`，详见[续作契约与验证](docs/pending.md)。
线性 rebase 也可用 `--record-conflict` 冻结队列；`--continue --resolved-index` 审定当前冲突步骤后继续，`--skip` 跳过当前步骤，另支持 `--abort/--quit`。原 HEAD 保持到全队列成功才一次发布，详见[rebase 续作契约](docs/rebase-pending.md)。
`ls-tree`、`show-ref`、`for-each-ref` 和 `count-objects` 可查询实际已提交树、引用与唯一对象统计；`ls-remote` 通过 HTTP/SSH 查询远端广告并明确标注对象尚未验证。格式、筛选、退出码与选项子集见[只读查询契约](docs/queries.md)。
`describe` 可按实际标签祖先生成可回读的修订名；`archive` 可将选定已提交文件的原字节导出为确定的 ustar，旧单模块需显式命名。元数据策略与选项边界见[描述与归档契约](docs/describe-archive.md)。
`bisect` 可冻结 good/bad 端点并保存测试判断，在完整 DAG 或第一父历史中选择候选；仅支持不切换工作区的流程，skip 歧义明确报告。用法与范围见[历史二分契约](docs/bisect.md)。
尚未提供签名、压缩 pack 或垃圾回收；自动合并也不证明行为符合开发者意图。
摘要用于内容完整性，不证明作者身份；本地拥有写权限的人仍可重写引用或删除整个仓库。
崩溃遗留的 `.uwgit/write.lock` 或 `.uwgit/index.lock` 需确认没有写进程后手动移除。
完整性检查和 bundle 当前需要将对象载入内存，尚未针对超大仓库做性能承诺。

## 验证

测试入口、环境要求及可选阶段。
常规回归、编译检查与日志在独立任务目录中执行；测试输出不纳入版本控制。
