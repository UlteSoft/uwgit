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
规范化函数体、指令/立即数相似度。尚未实现 BinDiff 的完整图邻域传播或基本块匹配。
地址/索引是位置，不是跨版本身份。重复内容只能确定等价候选，确定性配对必须显示 `ambiguous`。

参考 `uwvm2-ros/documents/ros/multimodule.md` 的真实 import/export 链接方式后，uwgit 不为宿主协议建立额外模块分类。
宿主名与字段名就是原始 import 字符串，各类外部项、签名和索引都应可比较。

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

## 对象格式 v1

仓库布局为 `.uwgit/{format,HEAD,refs,objects,tmp}`。format 文件为 `uwgit-repository-v1\n`。
HEAD 保存单个分支名；`refs/<name>` 保存 64 个小写十六进制字符及换行。
引用名使用受限简单名称，不能包含目录穿越路径。

对象编码：

| 字段 | 编码 |
|---|---|
| magic | `UWGO\0\0\0\x01`，8 字节 |
| kind | 1 字节，1=原始 Core wasm，2=commit |
| length | 8 字节无符号大端长度 |
| payload | 完整原始数据 |

对象 ID 是整个编码的 SHA-256，包括类型及长度。commit payload 是规范 JSON，字段固定为
`format:1, wasm:<blob id>, parents:[<commit ids>], message:<text>`。
不写入环境相关时间戳以保证相同内容/父链/消息得到相同 ID；作者身份与签名暂不进入协议。
普通 commit 创建单父提交；非快进 merge 与显式手工解决创建双父提交，父顺序为 `[ours,theirs]`。
读取器接受并验证多父 DAG，合并提交使用同一 v1 对象格式，不引入隐藏可变状态。

离线精确字节 patch 使用单独的[规范 JSON 格式](patch.md)，绑定完整原始文件摘要及可重放编辑，
不将未经复核的语义或最小性声明作为输入。它不取代携带 DAG 的 bundle。

bundle 编码为 magic `UWGB\0\0\0\x01`、u64be manifest 长度、规范 manifest JSON
`{format,head,refs}`、u64be 对象数，以及按 ID 排序的全部对象记录。
每条记录为 64 字节 ASCII ID、u64be 编码长度、完整对象编码。
重复键、非规范编码、重复对象、摘要不符、未知类型、缺父对象、错误对象类型、循环图和尾随数据均拒绝。

unbundle 在修改仓库之前验证全部输入；随后持锁检查本地状态、写入对象，最后发布目标引用。
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
跨布局索引重编号、语义等价或 rename 的历史证明、网络 transport、签名、pack/delta 压缩与超大仓库流式处理均待实现。
