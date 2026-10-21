# 标准配置与二进制审计

```sh
wasm-git inspect module.wasm --standard core1 --json
wasm-git diff old.wasm new.wasm --standard core3 --format json
wasm-git apply old.wasm change.uwgp --check --standard core2
```

`core1`、`core2`、`core3` 选择所允许的 Core 特性。
默认 `all-known` 保留旧接口行为，表示固定版本解码器认识的提案集合，不能称为官方 Core 3.0。
例如 threads、旧版异常编码和其他未纳入 Core 3.0 的已知提案，在 `core3` 下仍需单独标明不支持。
Component Model 仍不在范围内。

配置改变阅读与符合性报告，不改变存储对象或原始字节差异。
解码器始终使用已知的完整编码语法；标准配置单独判断这些编码是否允许。
因此在 Core 1.0 视图中，已知 SIMD 指令虽然不受支持，其立即数仍按正确长度读取，
后面的 `i32.add`、`end` 以及其他函数仍有正确的原始位置。
不支持的区域提供原始 hex、范围、识别依据和所需特性，并以二进制视图呈现。
已知但超出配置的内容标为 `recognized_but_disabled`，无法确定语法的内容标为 `unknown`；
已确认不符合编码规则的内容则标为 `invalid_encoding`，不把它冒充某个未来提案。
`supported` 表示特性允许；模块是否满足语法、索引和类型规则由单独的 validation 说明。
逐指令要求来自 opcode、显式操作数及已知的 memory/table、常量表达式上下文；
被引用的函数签名或 global 值型另在其声明位置报告。
例如 `call` 本身仍是 Core 1 指令，即使其 callee 的签名用了 v128；
不能把该 opcode 的 `supported` 当成 callee 类型或整个模块在 Core 1 合法的证明。

常量表达式读取先前定义的 global 的额外要求属于 `gc`；`extended_const` 则控制
i32/i64 的 add、sub、mul。Core3 同时开启二者，必须另用独立 feature 开关区分其来源。
导入的不可变 global 和普通函数中的 global.get 保持原有要求，mutable/self/forward/越界
仍须检查实际合法性。固定对照及 32 位 custom 名称边界复测。

普通 `br_on_cast/fail` 除 GC opcode 和各操作数要求外，还核对两个引用类型的关系。
同 heap hierarchy 但不满足普通子类型方向的转换，需要超出 Core3 的 `custom_descriptors`；
固定依赖的 continuation cast 放宽也单独标明。具体类型只使用严格完整的原 type 节建立
canonical 上下文，未知或无法解析的类型关系保持未证明；原模块的栈、标签和有效性仍独立验证。
固定类型关系和后续 MVP 字节的位置验证。

类型、节编码形式、段标志、地址宽度和上下文要求也需要检查。
不能只比较解码后的语义值：例如 data 段显式 memory 0 和隐式 memory 0，
以及显式引用类型和简写类型，可能有相同的解码结果，却属于不同年代的 wire 语法。
依赖库的 feature validator 可能已经丢失这种原始形式，审计还必须核对实际编码。
当前依赖还会接受裸 concrete heap index 作为引用值型简写；官方 Core 3 的简写只允许
abstract heap type，具体索引必须通过 `0x63`/`0x64` 构造引用类型。
工具会独立拒绝这种非法简写，并同时保留 validator 的实际返回值作为对照证据。

Core 2 的 `memory.init`、`memory.copy`、`memory.fill` 使用字面保留字节 `00`，
Core 3 才在这些位置使用 u32 内存索引。即使 `80 00` 解码后也是 0，
它仍需要新版内存索引编码；工具在每个内存立即数的实际范围上标明 `multi_memory`，
Core 1/2 视图为 `recognized_but_disabled`，并继续准确读取后面的指令。
secondary opcode 和 `memory.init` 的 data index 本来就是 u32，合法填充不因此被拒绝。
这项原始编码检查独立于依赖 validator，后者的实际返回值仍保留。
官方依据与正反例。

类型节在中途无法解码时，完整前缀内的声明仍保留；超出此前缀的具体 heap 引用、
array.copy 源/目标类型及 continuation 绑定输入/结果类型分别标明 unknown、角色和索引。
检查同时应用于已知指令边界及 global/table/local/typed-select 中的引用类型。
这些说明区分类型上下文是否可用，不代替模块索引与类型合法性的验证。
已识别提案的特性状态也单独保留，例如 stack switching 不能因此被当成 Core 3 特性。

类型引用在声明收集结束后核对，因而完整类型内指向后面未知类型的引用也不会漏标。
检查包括参数、结果、字段、父类型、descriptor/describes 和 continuation 的函数类型引用；
合法递归组中的前向引用保留原有含义。
函数声明、start、各类 export 和 element 的函数索引同样检查声明上下文。
tag 使用独立的 import/definition 合并索引空间，检查 throw/catch、try_table 的有标签 catch，
以及 continuation 的 tag 和 handler；catch-all 的 label 不会被当成 tag。
global 常量表达式向后引用的上下文也在最终声明前缀上复核。
声明上下文完整时，越界索引交给 validator 判非法，不把已知索引语法称为 unknown。
这些检查依据[官方模块验证上下文](https://webassembly.github.io/spec/core/valid/conventions.html)，
仍不把首个 validator 错误当成全部非法用法的逐项类型检查结果。

版本差异也可能来自验证规则。Core 1 的 `br_table` 要求全部目标标签类型严格相等，
现代 feature validator 沿用后续版本的匹配规则，不能只靠关闭 proposal 恢复这条旧规则。
其余 Core 1 检查通过后，工具在完整已知的 MVP 函数中检查控制标签栈，
将违反此规则的指令标为 `invalid_semantics`，
提供整条指令的原始范围和字节；Core 2/3 的判断仍遵循对应规则。
语法、类型或控制上下文不完整时不猜测历史标签类型。

对于解码器完全不认识的未来操作码，Wasm 没有通用的逐指令长度字段。
未知指令后的立即数可能恰好等于一个已知 opcode；搜索这样的字节不能证明找到了下一条指令。
工具保留该位置到表达式或函数体边界的原始内容，明确说明未解码范围；
只有能独立确认的函数体、节长度边界才用于继续阅读。
同理，未知类型不能靠扫描 `0x60` 来猜测下一条类型定义。
有合法长度框架的未知 section N 可完整保留，并继续处理其后的独立 section。

在已证明的指令或字段起点，已知整数超宽、超过规定长度、截断和明确错位的控制分隔符
会标为 `invalid_encoding`。合法 LEB 填充不因此被拒绝。
失败区域同时覆盖未解释的余下字节；该状态不表示后缀中的每个字节都已被证明非法。
无法证明的错误、未来 opcode 和未知类型构造仍保留为 unknown，原始 reader 错误另行保留。
判断基于固定版本 reader 的窄错误集合及输入前缀，不把所有解码失败统称非法编码。

值型读取先检查构造前缀，避免依赖库把 `FF00` 等未知前缀回退成裸 heap index，
再误读 locals、typed select 或常量表达式的后续字段。
locals 和 typed select 的前置检查中，`00..3f` 这些单字节正裸索引仍判非法；
其他未证明的类型布局保守标为 unknown，不推测未知前缀的长度。
无独立长度的常量表达式一旦出现这种未知值型，撤回后续条目、元数据及由错误边界产生的诊断，
原始范围延伸到节尾，直到下一个独立 section 才继续。
已知错误的声明数量虽标为 invalid，仍不能据此保留不可信的索引映射。
固定正反例和真实示例验证。

值型前缀检查也发生在声明条目提交之前。即使固定 reader 成功把裸 `FF00` 当成 heap index，
type、普通/compact import、table/global 和显式 element 引用类型也不会据此提交后续声明。
未知值型的起始字节单独定位；当前 entry/group 到节尾保留为 unknown 二进制。
完整前缀仍可解释，未知组内看似完整的前置成员也不会单独入索引映射。
blocktype 和 heaptype 本来允许非负 s33，`FF00` 在这些位置合法表示 127；
显式 `63 FF00` 的引用类型同样保留已知语法，越界与否由完整上下文及 validator 判断。

CLI 的函数分析复用二进制审计结果作为入口：非 custom 节不完整或存在已确认的
`invalid_encoding` 时，`function_analysis.available=false`，并说明失败位置。
原始审计、已知函数位置和字节补丁继续提供。
完整已知语法中仅有 feature 禁用、validator 错误或特定标准的 `invalid_semantics`，
不单独触发这一入口限制；opaque custom payload 也不阻断它。
此门槛约束 CLI 的 normalize/comparison，独立低层 parse API 仍是原有 best-effort reader。
若 permissive validator 接受了回退值型，但主审计已撤回 Core 结构，模块总览也不能显示
`valid_with_all_known_features`；其状态为 `failed_or_unsupported`，
实际验证器是否接受仍保留在 `standard.validator_valid`；其输入由 `standard.validator_input` 明确记录。
固定回归与实际版本流程。

已知 compact imports 提案的 Compact2 只编码一次共享 TypeRef。
`import[0]/group[n]/shared_type` 保存 kind 与整个 TypeRef 的真实原始区间，
其中值型/limits 的更细特性证据仍使用实际字段子区间；名称条目说明它实例化哪个 shared_type。
共享类型的静态 wire feature 不再重复标在名称上，名称列表为空时也照常报告。
实际声明和组合索引仍按名称数量登记：空组不创建实体，不产生类型索引依赖、mutable import 或 tag 结果签名语义。
额外 memory/table 及未知声明前缀属于实际实例，仍标在对应名称条目处。
读取某个名称的 `supported` 只说明该物理条目的直接要求，需同时检查共享类型和整个 group；
这不把 compact imports 纳入 Core 3。完整名称列表成功展开之后才发布该组证据，失败不遗留部分共享类型。

import/export 的名称错误也从失败 entry/group 的可信起点按已知布局核对，
不使用 reader 的错误 offset 猜测名称起点。Compact1 按名称、TypeRef 的顺序逐项读取；
Compact2 必须先确认共享 TypeRef，再读取名称列表。
未知 external kind、未知值型前缀或无法证明的类型布局会立即停止此检查，
不会越过它们再把后置字节解释成非法名称。
在可证明的名称字段中发现非法 UTF-8 时标为 `invalid_encoding`，
并在 `undecoded` 的字段子区域定位首个非法序列；不完整序列的范围止于该名称自身末尾。
固定 reader 的原始错误及 offset 同时保留，完整失败组仍不发布声明或索引。
合法空名、NUL 和其他合法 Unicode 不因名称内容被判非法；重复 export 等语义限制仍由验证处理。
固定 reader 的字符串资源上限错误保持未分类，不把它当成 Core UTF-8 或长度编码规则，
也不把 custom 元数据的 reader 投影应用到 Core 链接名称。

`FuncExact` kind `20` 在 import TypeRef 中属于 custom descriptors 提案；
[固定 export reader](https://github.com/bytecodealliance/wasm-tools/blob/v1.249.0/crates/wasmparser/src/readers/core/exports.rs)
则明确禁止把它用于 export descriptor。在可信 export 名称之后出现该 kind，
会精确定位这一字节并标为 `invalid_encoding`，包括 all-known 配置；
这与已知但被所选标准禁用的合法提案编码不同。

自动三方合成同样检查完整输出的 all-known 标准报告，不能只调用宽松 validator。
未变的上下文若已有 unknown 或 invalid_encoding，仍会阻止新结果发布。
整份原字节选择和明确手工解决属于保存既有或指定字节，继续报告实际审计状态。
固定仓库分叉和字节保留验证。

外层 section 长度无法读取或超出文件时，节本身标为 `invalid_encoding`，
不再把截断但看似完整的 payload 交给类型/指令分类器。
custom 的外层名称长度和 UTF-8 同样属于 Core 编码；这些错误与合法名称之后的
custom 固定约定不匹配分开，后者仍只作 opaque，不影响 Core 合法性。
未识别 custom payload 使用 `custom[n]/payload/opaque`；producers 值条目使用
`custom[n]/producers/{language|processed-by|sdk}/value[i]`，其中 `i` 为字段内的物理序号。
已识别的 `name`、`producers`、`target_features` 固定命名空间保留。
任意名称与版本内容只保留在描述及对应 span 的原始字节中，不嵌入路径；
包括 NUL、Unicode、斜线、百分号和超长合法 UTF-8，路径仍为不随名称增长的有界 ASCII。
物理序号不证明跨版本身份。`trace --path` 精确匹配当前路径，不提供旧名称路径别名，
也不进行文件系统或百分号解码；旧调用应重新 `inspect` 或改用 `--range`。
严格 custom 约定不满足规范识别条件时，整个 payload 仍转为 opaque；
name subsection 12/13 仍未识别并导致整个 name payload opaque，本轮不新增格式支持。
固定依赖对字符串有 100000 字节资源上限。超过该上限的合法 custom 外层名称，
先独立检查原始 section frame、节内 u32 名称长度及完整 UTF-8，再在临时 reader 输入中
将名称长度的首字节改为 `00`，其余原名称字节成为该视图中不解释的 custom data。
该视图长度、section header 和所有非 custom 字节及其偏移不变；临时 custom data_offset 不用于原始审计。
all-known/selected validator 及忽略 custom 的函数 parser 使用这个相同规则的 reader 视图。
`standard.validator_input.kind` 为 `original_bytes` 或 `custom_name_projection`；
`projections` 逐项列出原始名称 path/name_span、实际改动的单字节 byte_span 和前后 hex。
`validator_valid` 表示对该明确输入运行固定验证器的实际结果，不声称对未改动的原始串绕过了依赖上限。
普通名称不投影、不复制整个模块；不合法或越出自身 payload 的名称也不投影。
原始审计、特性收集、验证错误 byte_context、diff、patch、对象摘要及仓库存储始终使用原始字节。
合并判断 custom 对应关系同样读取完整原始名称，不能使用投影后的空名。

节的重复/乱序错误定位到该节头部；受影响的声明索引映射在解释前整体撤销，
避免迟到的 import 使此前的索引推断失真。已知指令边界仍保留，不可信的类型/目标上下文标为 unknown。
函数对应关系不可信时仅保留每个 code section 内的物理 `defined_index`，`function_index` 为 unknown。
复现样本和确定性测试。

原始差异覆盖被标为不支持、未知、格式错误及不透明 custom 的内容。
字节补丁绑定完整前后摘要并验证重放结果；标准配置不能把这些字节排除在变更之外。
函数相似度、完整解码、标准符合性和精确字节重放是分别报告的结论。
函数解释层使用全部已知编码，JSON 的 `function_analysis` 明确记录这个范围，
它不为所选标准作合法性背书。

`standard.validator_error` 保留验证器的首个错误，并给出最多 16 字节的原始
`byte_context`（半开范围及 hex）与 `locations` 结构位置。
`contains_offset` 表示范围覆盖报告偏移，`ends_at_offset` 表示范围恰好结束于该偏移；
零长度位置使用 `empty_at_offset`。验证器可能报告操作码位置或读取后的游标，
因此边界前后候选同时保留，这些位置不能单独证明错误由哪个条目造成。
EOF 和越界偏移分别明确标记，原始报告偏移不被改写，字节窗口始终限制在实际文件内。
这不会把首个验证错误扩张成所有指令都已完成类型检查的结论，也不改变原始 ByteEdit。
确定性回归与真实示例验证。

审阅依据为官方 [Core 3.0 二进制节定义](https://webassembly.github.io/spec/core/binary/modules.html)、
[类型编码](https://webassembly.github.io/spec/core/binary/types.html)、
[指令编码](https://webassembly.github.io/spec/core/binary/instructions.html)和
[历次标准变更](https://webassembly.github.io/spec/core/appendix/changes.html)。
逐节审阅及参考 `uwvm2` parser 的记录。
