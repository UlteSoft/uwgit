# uwgit 的二进制审计与版本模型

## 依据与范围

[WebAssembly Core 二进制规范](https://webassembly.github.io/spec/core/binary/modules.html)
给出了 section 边界和标准条目的编码；[指令编码](https://webassembly.github.io/spec/core/binary/instructions.html)
决定 opcode 及立即数边界。Core 验证规则与 custom 元数据约定的识别规则分开实现。
[标准 name 约定](https://webassembly.github.io/spec/core/appendix/custom.html)、
[producers 约定](https://github.com/WebAssembly/tool-conventions/blob/main/ProducersSection.md) 和
[target_features 约定](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#target-features-section)
是目前的元数据识别来源；识别器有意接受保守子集，扩展或不规则格式回退为 opaque。

[BinDiff 手册](https://www.zynamics.com/bindiff/manual/#chapUnderstanding)
通过唯一特征建立函数锚点，再在调用图邻域中缩小匹配候选，并区分相似度和置信度。
本项目借鉴唯一锚点、分层匹配及歧义标记；当前匹配顺序是导入/导出角色、完整已解码函数体、
规范化函数体、指令/立即数相似度，并用已建立的非歧义 callee 对应补充引用邻域候选。
这里的邻域步骤要求逐条解码指令和非引用立即数相同，每个函数引用都由已有对应支持；
它不是 BinDiff 的完整图匹配或基本块匹配。
地址/索引是位置，不是跨版本身份。重复内容只能确定等价候选，确定性配对必须显示 `ambiguous`。
相似度阶段在贪心分配前确定同分候选，已选走的候选不会使剩余配对突然成为无歧义。
较早匹配阶段发现的重复候选还会保留到后续阶段，包括当时没有配走的候选端点。
`confidence` 是解释匹配结果的启发式数值，不是跨版本身份的统计概率或历史证明；
`ambiguous=false` 只表示当前匹配规则没有发现同等候选。

无导出函数的引用上下文按 callee 到 caller 的依赖顺序迭代计算，不借用 parser 的临时函数序号。
imports 与 export 角色先提供锚点；没有角色锚点的递归依赖、越界函数引用及其未解析依赖者明确标为不完整。
`reference_context_complete` 只描述静态直接函数引用上下文是否可解析，不证明运行行为或历史身份。
不完整上下文不参与强函数体匹配，剩余相似度候选保留歧义及较低置信。
原始函数体相同也要核对引用上下文，避免将相同的 `call 1` 配到不同目标。

函数差异还比较按 opcode 序列对齐的 `call`、`return_call` 和 `ref.func` 位置，
返回两侧原始 operator index/offset、函数索引、解析目标和独立静态函数候选。
caller 的配对仍使用普通函数 matcher；callee 的确定对应只采用下文的独立依赖图，
不借用同名 export 角色、相似度或已消费的重复项来说明目标相同。
相同 import tuple 必须在两侧全域各出现一次，否则保持歧义，包括没有 matcher 记录的重复项。
`call_bindings` 将索引重定位与目标重绑定分开；目标实现修改本身不等于 caller 改绑。
只有重复 import 或未确定的目标提示、且没有其他已知修改时，放入 `call_binding_notes`，
不据此把函数计作已知修改。
`direct_calls_changed` 保持原始数字索引列表的含义；绑定变化由新增证据表达。
opcode 对齐和 defined target 对应都是阅读辅助，`identity_unproven=true` 不被消除。
每条记录的 `match_scope` 披露排除 export 角色的范围；可空的 `dependency_proof` 引用共享图根。
共享图保留既有 JSON 字段名 `export_dependency_graph`，现在也供调用点使用，并为没有 export 的模块构建。
没有唯一证明且索引改变时保留 ambiguous/unresolved；同索引、无歧义且仅修改被调函数实现时不制造绑定事件。
full text 展示调用根与逐引用见证，short 披露证明根数量；循环不能借调用或导出角色自举证明。
这些解释不改变精确字节审计，也不让物理 `trace` 查询自动扩展到语义依赖。

参考 `uwvm2-ros/documents/ros/multimodule.md` 的真实 import/export 链接方式后，uwgit 不为宿主协议建立额外模块分类。
宿主名与字段名就是原始 import 字符串，各类外部项、签名和索引都应可比较。

export 的原始 target-key 增删继续保留索引及 exact 标志，不能直接视为名称成员增删。
另用 `export_binding_notes` 按 `(name,kind)` 配对，保存两侧原始索引、完整目标及独立候选。
唯一候选现在由独立静态函数依赖图建立，不使用 export 角色、函数 ID 或 fingerprint 来证明对应。
完整结构化 import binding tuple 和无静态函数引用的完整 typed body 提供初始候选；
两侧全域对应组都只有一个成员时才接受，已配对成员仍计入重数，不能通过消费重复项制造唯一性。
随后逐层比较 type_id、locals、完整 opcode 和立即数序列；每个 Call/RefFunc 引用位置都必须由前一层的双向唯一对应支持。
`return_call` 保持自己的 opcode；重复引用逐位置保留，不因共享同一 callee 而合并证据。
循环、越界目标、未知 opcode/立即数或依赖中的歧义不提供证明。

JSON `export_dependency_graph` 保存每对模块共享的节点，`export_binding_notes[].dependency_proof` 只引用根及 depth。
节点记录两侧函数索引、类型、种类、层级、import tuple，以及每个引用两侧的 operator 序号、原始字节 offset 和目标索引。
每条引用指向更低层节点；节点不按 export 复制依赖闭包。原匹配器的独立视图仍清除 export 角色与旧 fingerprint，
仅用来说明没有唯一证明的叶节点歧义，不能替代依赖图建立唯一对应。

这里的 type_id 和非函数立即数按现有 IR 值比较，不递归证明类型图或其他索引空间的语义对应。
所有结果均保留 `identity_unproven=true`，不证明历史身份、运行行为、Core 有效性或宿主 import 实现相同；
`target_changed=false` 只表示此静态候选范围内的对应，不表示整个程序等价。
其他 kind 的 export 只保存目标变化，不推断实体对应；原始 ByteEdit、对象、patch 和物理 trace 不受候选解释影响。

## 三条互补的数据链路

1. `原始字节 → SHA-256 对象 → 提交 DAG`。存储层不依赖解释器、不重编码文件。
2. `原始字节 → 物理 section framing → 标准条目/表达式/指令 + diagnostic`。
   每个对象都有原始字节区间；无法认识的内容仍然有物理证据。
3. `已解码函数 → resolve → normalize → 函数匹配/指令差异`。
   这一层提供阅读辅助，不能覆盖或抵消原始字节的变化结论。

`inspect` 和 `diff` 总是先调用审计层。旧函数管线无法处理未知内容时返回
`function_analysis.available=false` 和原因，审计结果继续输出。

每个标准 section 都独立在已知长度内解码。未知 opcode 没有可信的立即数长度，
所以解码停在该 opcode 之前，余下函数作为一个 opaque 区间；下一函数仍使用 code 中的 body size 定位。
已知标准内容损坏会报告 `core_decode`、`operator_decode` 或 `validation`，
不会按 custom 元数据的宽容策略悄悄当作合法标准条目。
标准向量解析失败时仍保留此前完整条目，失败项的完整剩余字节作为 undecoded，不按报错的内部位置截掉前缀。
table/global/element/data 的表达式没有独立 byte length。恢复时从已证明的表达式起点严格检查指令，
即使上游宽松 `ConstExpr` 成功，也不能用未知 typed-select 值型之后的表面 End 证明后续字段。
已知指令前缀保留原始位置；未知指令及剩余 section 作为 opaque，撤回其后的 data bytes、元素和条目边界。
恢复 horizon 也在未知前缀处停止，不扫描未知内容寻找 End；下一 section 仍按外层长度读取。
data 的确定错误分类单独检查 flags、显式 memory index 和严格 offset expression，只有这些字段已证明，
才检查 data length 与 payload。因此真实 active/passive 长度截断或溢出仍为 `invalid_encoding`，
未知表达式后的假长度错误不能成为非法编码证据。完整表达式之后的 data bytes 始终只是数据。
独立 validator 的失败可以保留；前端的 unknown 表示语法边界未证明，不表示模块有效。
element 模式、显式 table index 和 expression-items 特性由八种已知 flags 独立记录，
正常解码、表达式恢复和未知声明类型之前的已知 flags 使用同一规则；未知 flags 不套用现有 bitfield。
已有完整表可证明失败初始化器之前的 additional-table 特性，但失败表不进入声明索引。
这些前置证据不授权解释未知 type、item、后续条目或目标索引。
type/import/table/global/element 的值型探测只从可信 entry 起点逐字段读取，借用外层 section 长度，
不再要求未知类型之后的整项 reader 成功。未知后的 EOF、假 count、limits 或 flags 错误不能抹掉类型起点；
真实前置错误和未证明的 offset expression 则先停止，不跳过它们去寻找未知字节。
失败项不发布声明，完整前条目和后续独立 section 继续定位。
同一严格前缀扫描还可保留未知类型之前的名称、compact discriminator/count/kind、完整前置 import type，
以及 `40 00` table initializer 标记。它们只成为 carrier 上的原字节证据，不生成失败组的声明子节点。
consumer 核对未知起点一致且所有事实止于其前；完整类型仅保留 wire 特性，临时类型依赖撤回，
不发布实例或推导未知后的名称数、flags、limits。
type 的同一严格扫描还记录失败组内已知的 rec/sub/composite、数量、字段、完整值型和提案修饰符。
每个证据跨度止于未知起点前；失败组中完整的前成员仍不发布，完整引用值型的临时类型依赖也撤回。
Core 1 的基础字段边界证据与 SIMD/GC 等实际类型要求分别显示。
type 的确定失败也复用该扫描器，只接受上游与严格字段读取均证明的整数宽度/长度或截断错误。
`undecoded/type_error` 精确标出失败字段，EOF 可为空区间；剩余原字节不解释为后续字段或声明。
实现资源限制、未知构造及不支持的继承布局不授权更晚的错误判断。
import 同样只在上游窄白名单与严格逐字段扫描共同证明失败时新增 `undecoded/import_error`。
名称截断覆盖长度 LEB 和本 section 内实际剩余 payload；原有 UTF-8 诊断优先，资源上限不当成编码错误。
已知 TypeRef 完整读完并由固定 reader 再核对后才保留前置类型事实；未知 flags、tag attribute 或布局先停止。
table/memory limits 按全特性 reader 的 u64 wire 读取，即使地址标记为 32 位，也不误报合法 padding。
失败 compact group 不发布任何成员或索引，剩余字节保持 undecoded。
table/memory/global/tag 与 import 共用严格头字段读取；确定失败的具体字段由各自 `*_error` 叶定位。
table 定义的 `40 00` 头与导入 TableType 分开；完整 table/global 头后的初始化器不借此诊断头字段错误。
未知 flags、保留字段和 reader 资源限制均先停止。
已知向量 section 的外层 count 与 start/data-count 标量按 section ID 分派，物理 payload 起点不代表 count 语法。
function/export 的确定字段错误同样精确定位；已成功字段后的尾数据、旧 UTF-8/Exact 诊断和未知 kind 边界保持。
含 offset 的 element/data 只在严格根表达式已闭合后读取后续元数据；未知类型/指令或嵌套 End 不能授权猜测字段。
确定字段失败由 element_error/data_error 定位；code_error 只针对函数体 size/bytes 外框，
完整帧内部 locals/指令错误保留原 decoder 的归属。
reference-only 槽的 `7b..7f` 是已知非法类型，使用实际 reader 错误与严格字段位置共同证明并定位单字节；
未知前缀及构造器内部未知 heap 不套用该诊断。
完整函数外框中的 locals 错误由实际 reader 错误与有界字段读取共同证明，新增 opaque/locals_error 精确叶；
累计或资源错误先停止，完整 locals 后的失败仍归 operator/expression。
七种单 HeapType 指令仅在实际 reader 错误与独立 opcode/一字节类型证明同时成立时新增 opaque/heap_type_error；
FB22 的 u32 索引排除在外。四种双 heap cast 在未知 flags 处停止，不能用后续 depth 错误证明非法；
常量表达式复用同一前沿保护。
双 HeapType cast 另在已知 flags/depth 后区分 source/target 字段；target 证明还要求完整 source HeapType 与
RefType 构造均成功，不能穿过 exact/concrete 实现上限或将未知负编码归一化。
br_table 的整数失败另在独立有界重读后定位 count、target[N] 或 default；只有实际错误与字段失败均可证明才新增叶，
原 parent 分类保持，完整表后的失败仍归后续 operator/expression。
try_table 的 catch 字段只在完整 BlockType 前置证明后定位；FuncType 使用非负 s33/u32 全范围，
reference 内的实现上限、未知 kind 与资源 count 会阻断后续字段。
memarg 在完整未知 flags 处停止已知语法证明，不能用后续 index 的 EOF/宽度错误标记已知非法；
已知 flags 的 alignment 与 u64 offset 编码仍独立于语义验证。
call_indirect/return_call_indirect 在两个完整 u32 字段中定位首错，不套用类型实现上限或 Core1 的物理读取模式；
原父证据保持，只新增精确字段及其派生诊断。
memarg 的 flags/显式 index/offset 仅按完整已知前缀定位首错，保留 u32/u64 全范围；
未知 flags 阻断后读，完成 offset 后的 lane EOF 不归此字段。
不完整 import section 之后的 defined index 仍可定位，全局 function index 则明确报告未知。
未知 section/提案保留原文并显示无法验证；验证失败与未知扩展暂不可判定共同使用 `failed_or_unsupported`。

所有 offset 均为原始文件的字节偏移，区间右端不包含在内。重复 custom section 按出现次序编号，
不会因名称重复而合并。`semantic_changes` 的 section/条目路径按位置对齐，不宣称跨版本对象身份；
例如插入 import 后的位置移动可能形成多项解释变化。函数匹配另行提供候选对应关系。

## 不漏报与最小性的契约

`audit.changed` 直接比较原始文件是否相同；不依赖 hash、名称、验证成功或函数对应关系。
每个编辑保留旧/新位置和原始字节。按有序、不重叠旧区间应用编辑后必须逐字节等于新文件。
回归测试同时验证该重放性质和小规模输入上的最短 insertion/deletion 距离。

单次 Myers 的距离上限是 1024；全局搜索先使用最多 6,000,000 个搜索工作单位。
无法完成时，从两侧内容寻找唯一的 32 字节窗口并逐字节核对，再选择单调、不重叠的 anchors，
以定位插入/删除后发生偏移的函数与数据。窗口索引最多保存 65,536 个候选，重复内容不作为唯一锚点。
各个间隙共享剩余预算；全局与局部 Myers 合计最多 8,000,000 个搜索工作单位。
锚点扫描、输出和索引构建另按输入/输出规模消耗工作，不计作 Myers 的搜索单位。

回退永不丢弃差异，但明确取消全局最小性结论。局部预算耗尽时，等长间隙列出不同字节区间，
非等长间隙保留完整替换。相同窗口只能说明这些字节相等，不能证明对象的历史身份。
不能把锚点分块后的局部最小宣称为全文件全局最小。

GC 类型记录 rec group、subtype/finality/supertype、共享标记及完整复合类型；
指令记录完整立即数，额外提案使用保留完整 Debug 字段的回退。
NaN 按原始位模式比较；多内存 memarg、bulk init 索引、EH catch 类型/tag/label 不可丢失。
函数指纹仍用于索引候选，SHA-256 对象摘要才是历史内容寻址依据。

旧 CFG/调用图分析并不具备完整的 EH、GC subtype 或未知提案语义，不能据此证明程序行为等价或安全。
审计工具不执行待比较模块。

## 原始对象与文件树

仓库对象布局为 `.uwgit/{format,HEAD,refs,objects,tmp}`，另有可选的 tags、reflog、index、stash、config、remotes。
format 文件为 `uwgit-repository-v1\n`。工作区命令见[命令矩阵](git-workflows.md)，网络服务见[服务协议](server.md)。
HEAD 保存单个分支名；`refs/<name>` 保存 64 个小写十六进制字符及换行。
引用名使用受限简单名称，不能包含目录穿越路径。

对象编码：

| 字段 | 编码 |
|---|---|
| magic | `UWGO\0\0\0\x01`，8 字节 |
| kind | 1 字节，1=原始 Core wasm，2=commit，3=文件树 |
| length | 8 字节无符号大端长度 |
| payload | 完整原始数据 |

对象 ID 是整个编码的 SHA-256，包括类型及长度。commit payload 是规范 JSON，字段固定为
`format:1, wasm:<blob id>, parents:[<commit ids>], message:<text>`。
不写入环境相关时间戳以保证相同内容/父链/消息得到相同 ID；作者身份与签名暂不进入协议。
普通 commit 创建单父提交；非快进 merge 与显式手工解决创建双父提交，父顺序为 `[ours,theirs]`。
读取器接受并验证多父 DAG。旧 format 1 提交和对象的编码、摘要保持不变。

多文件提交采用 format 2，以 `tree` 引用 kind 3 对象，省略 `wasm`；
其规范字段顺序为 `format, parents, message, tree`，可选的 `legacy_path` 在末尾。
树 payload 为 `{format:1,entries:{path:blob_id}}`，路径按 UTF-8 字符串排序，目录由路径隐含。
空映射就是空文件树，文件删除不以空 Wasm 代替。路径禁止绝对路径、空段、点段、控制字符、
元数据目录及文件/目录前缀冲突。每个 blob 仍保存完整原始模块。

旧提交没有文件名。升级时明确记录 `legacy_path`，后代提交保留该映射；不从内容或名称猜路径。
同路径的新增、删除、修改独立参与三方合并；多个路径的冲突或非法树必须在安装对象及发布引用前发现。
历史重放先在内存中完成全部文件树，最后一次发布分支引用。已有 index 的工作区还需预检全部目标路径，
避免提交成功后才发现未追踪文件会被覆盖。外部并发写入和发布后的实际 I/O 失败仍会明确报告部分完成状态。
工作树的文件/目录转换由同一完整计划预检，核对所有受控路径和被替换目录的完整子树，
发布前重新比对计划；依次删除受控文件、清理受控空目录、写入目标。
非递归目录清理保留同级内容，任何未追踪文件、未受控空子目录或符号链接阻碍都会拒绝转换。
--resolved-index 则是明确的元数据提交：持有 index.lock 读取完整规范暂存树，
再以 write.lock 校验双方不可变 ID、分支、共同祖先和全部对象，记录双父结果与当次逐文件审计。
它不进行工作树同步，也不把未暂存修改作为解决结果。

离线精确字节 patch 使用单独的[规范 JSON 格式](patch.md)，绑定完整原始文件摘要及可重放编辑，
不将未经复核的语义或最小性声明作为输入。它不取代携带 DAG 的 bundle。

bundle 编码为 magic `UWGB\0\0\0\x01`、u64be manifest 长度、规范 manifest JSON
`{format,head,refs}`、u64be 对象数，以及按 ID 排序的全部对象记录。
无标签时保留旧版 format 1 manifest 的精确编码；有标签时显式使用 format 2，增加 tags 映射。
含 tree 或 format 2 提交时显式使用 format 3 manifest；旧对象集合仍使用原 format 1/2 编码。
仓库 marker 与对象 envelope 不变，提交 ID 不因传输或增加标签而变化。
每条记录为 64 字节 ASCII ID、u64be 编码长度、完整对象编码。
重复键、非规范编码、重复对象、摘要不符、未知类型、缺父对象、错误对象类型、循环图和尾随数据均拒绝。

unbundle 在修改仓库之前验证全部输入；随后持锁检查本地状态、写入对象，最后发布目标引用。
它选择 bundle 的 HEAD 提交导入指定接收分支。
已有本地 index 时，unbundle 拒绝直接导入当前分支，应导入 incoming 分支后再 merge，以保留工作区预检与同步。
若导出仓库的 HEAD 尚未有提交，
即使其他分支已有提交，该 bundle 也不能用于 unbundle；应先 switch 到已有提交的分支再导出。
clone 保留全部分支与 unborn HEAD，不受这项源提交选择限制。
输入验证失败不写入任何对象；写入过程发生 I/O 中断可能留下未引用对象，但不应提前更新引用。
clone 先读取一致快照，再写入新的目录；目标目录必须不存在。
仓库版 inspect/diff/patch/apply 的输入使用已验证快照；两侧引用批量解析并返回实际提交 ID。
新文件输出使用同目录临时文件写全并同步后 hard-link 原子发布，拒绝覆盖任何已有目标，再同步父目录。
读对象重新核对 SHA-256。写锁保护协作进程；操作系统用户的任意外部篡改不属于锁提供的互斥保证。

## 验收边界

当前实现针对上述审计和历史协议测试，并通过 `tests/spec_corpus.rs` 接入固定版本的官方 Core WAST 语料。
外部测试读取所有嵌套 `.wast` 文件，记录源文件/模块摘要、解码诊断、恒等比较及字节突变的重放结果。
输入 archive 和完整文件集合必须满足 `tools/spec-corpora.json` 中固定的摘要与数量。
这里的语料测试不实例化模块、不执行 runtime 断言，不能宣称执行语义的全量一致性认证。
`WasmFeatures::WASM1/2/3` 是当前验证器的 feature profile，并非完整的历史规范校验器；
已识别的历史规则差异必须单独列出，不能作为 validator conformance 通过。
固定版本 wasmparser 决定已知提案范围，
后续标准/私有提案即使无法解释仍须原样存储、定位和报告。
当前已实现受限的结构化三方合并及带预期 HEAD 检查的手工解决，见[合并说明](merge.md)。
区间历史查询沿全部父边提供审计编辑脚本下的影响证据，保留重复内容的不确定性及回退/预算边界，
不将物理对齐作为函数身份或作者来源证明，见[历史追踪说明](trace.md)。
HTTP/SSH 传输共享已验证的对象及 bundle 闭包。跨布局索引重编号、语义等价或 rename 的历史证明、
签名、pack/delta 压缩与超大仓库流式处理均待实现。

常量表达式中读取先前定义的 global 记录 `gc`，与整数算术的 `extended_const` 独立。
custom 外层名称先检查长度是否超过本节剩余字节，防止固定 reader 在 32 位地址空间中溢出；
局部变量预扫描先读取完整 repetition count 并检查函数内累计 u32 数量，只有实际 reader 能继续时
才探测类型前缀；累计溢出保留真实错误和失败组起始的 opaque 后缀。
类型声明预扫描先通过函数参数/返回值、结构体字段、递归组的数量准入，以及父类型、describes、descriptor
索引的 PackedIndex 容量检查；资源拒绝后不发布未读取的类型前沿。
Typed select 的预检查先遵循 pinned reader 的数量资源限制，再读取类型；
超过实现限制时保留真实资源错误，不能从未读取的后缀推断类型。
24 条 SIMD 指令在真实 reader 的 EOF 后定位 const 现存字节或首个缺失 lane；
lane 是普通 u8，memarg 未完整读取时不能到达它。
17 条单索引主 opcode 在真实 reader 的确定错误后定位一个完整 u32 字段；
catch/delegate 的前置控制帧检查不能被错误叶绕过。
Core3 GC struct/array 的 FB 次级 opcode 0..19（除无立即数字段的 15）按 wire 顺序定位首个失败的 u32；
type/field/data/element 索引及 array.new_fixed 的元素数量保持各自角色，不套用 HeapType 上限。
FC 次级 opcode 8..17 只在次级 opcode 完整识别后，按 wire 顺序定位首个失败的完整 u32 索引字段；
失败或未知的次级 opcode 不授权读取后续操作数。
`memory.size` / `memory.grow` 仅在真实 reader 的确定整数/EOF 失败后定位一个完整 u32 字段；
完整索引、旧版保留零 wire 规则和命名空间验证分开处理，不读取后续指令。
