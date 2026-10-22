# 标签描述与原字节归档

新增 `describe` 与 `archive`，分别用于为已提交修订生成可读名称，以及分发已提交 Wasm 原字节。接口参照 [Git describe](https://git-scm.com/docs/git-describe) 和 [Git archive](https://git-scm.com/docs/git-archive)；tar 编码依据 [GNU tar 的标准格式说明](https://www.gnu.org/software/tar/manual/html_node/Standard.html)。本程序的对象、时间与标签模型有明确差异，下列范围不表示兼容 Git 的所有选项。

## describe

```sh
wasm-git describe DIR [REV] [--tags] [--exact-match] [--always] [--long] \
  [--first-parent] [--abbrev N] [--match GLOB]... [--exclude GLOB]... \
  [--no-match] [--no-exclude] [--json]
```

REV 默认 HEAD。查询只使用一个经验证的仓库快照，包含所有已安装对象以及实际引用；不读取 index、pending 或工作文件。现有标签全部是 lightweight，因此默认考虑全部本地标签，`--tags` 显式表达同一规则；Git 的默认 annotated-only 不适用本程序。分支与远端 tracking 不作为标签候选，不伪造注解、tagger 或日期。

候选必须是目标的祖先。精确指向目标的标签优先；其他候选按 `目标祖先闭包 \ 标签祖先闭包` 的提交数量排序，数量相同时按 ASCII 标签名称排序。该距离不是最短路径的边数。`--first-parent` 同时限制目标及标签的祖先遍历。计算所有匹配标签，不使用 Git 的默认十个候选上限；因为未存储日期，平分时不推断新旧。

普通输出为精确标签，或 `TAG-N-gABBREV`；`--long` 也为精确标签保留 `-0-gABBREV`。`--abbrev` 默认 12，接受 0–64，非零时至少使用 `max(4,N)` 位，并延长到在整个已验证对象存储中唯一。0 只输出匹配标签；没有候选时，`--always --abbrev=0` 使用完整 64 位提交 ID。无候选且未使用 always 明确失败；`--exact-match` 即使配合 always 也必须命中精确标签。long 与 abbrev 0 在访问仓库前拒绝。

多个 match 取并集，exclude 优先排除；两种列表各自可由 no-match/no-exclude 按参数顺序清空。匹配完整标签名，只支持 `*`/`?`，不支持 brackets 或反斜杠转义；模式最多 1,024 字节，拒绝控制字符。普通开关重复、未知参数、无效整数和选项组合明确拒绝。值恰好为 `--help` 时仍是值，不会被错误当成帮助。

JSON 保留实际完整 commit/tag_commit、距离、exact、first_parent、请求的缩写长度和实际唯一缩写、筛选后本地标签数量及明确 selection_policy。`evaluated_tags` 统计通过名称过滤的标签，包含随后因非祖先或非精确而排除的标签。description、fallback、long 与 match/exclude 明示输出如何产生。

## 描述名作为修订

`TAG-N-gABBREV` 可交给现有修订入口，包括 rev-parse、show、archive 和 ancestry 后缀。首先保持所有现有精确引用与歧义规则；完整引用同名时优先使用它，不偷偷改变其含义。

没有精确引用时，可识别 `非空正常层级 ASCII label-十进制提示数字-g十六进制后缀`。label 最多 128 字节，首字符为字母或数字，其余为字母、数字、`.`、`_`、`-`、`/`，层级组件不得为空、`.` 或 `..`；后缀为 4–64 位，接受大小写并按规范小写 ID 查询。整体名称可超过 128 字节。后缀必须在全部存储对象中唯一且对应 commit，非 commit 或歧义明确失败。

名称和数字只是可读提示，不是经过认证的标签历史或距离；真正修订绑定来自唯一的已验证对象 ID。即使标签后来移动，仍可按该 ID 识别原提交。`~N`/`^N` 的既有父链校验继续生效。和其他普通修订一样，同名 branch/tag 的原歧义保护仍在，必要时使用完整 ID 或带 namespace 的引用。

## archive

```sh
wasm-git archive DIR REV --output|-o NEW_TAR [--format tar] \
  [--prefix PREFIX[/]] [--legacy-path NAME] [-- PATH...]
wasm-git archive --list|-l
```

从单个已验证快照读取 commit 修订或完整 tree ID。直接 tree 不冒充 commit；tree 前缀和裸 Wasm blob 不猜成命名树。未知指令、section 或 custom-section 的字节原样导出，不做反汇编后重建，不读取未暂存编辑或本地属性。

PATH 支持精确文件、目录后代和根 `.`/`./`；尾斜线只匹配后代，每个选择器均须匹配，否则不发布任何文件。普通路径为规范相对路径，不接受内部 `.`/`..` 或 `.uwgit` 组件。prefix 是相同约束的相对目录，缺少单个尾斜线时补上；不接受空值或越界前缀。选择后按原路径排序，再添加 prefix。

旧单模块提交必须显式 `--legacy-path NAME`，即使旧提交已有 legacy anchor 也不猜名。显式导出名称可以不同于 stored anchor，JSON 同时报告两者；不会修改存储映射。命名树不接受 legacy-path。空命名树可以导出，仅包含结束块，和需要显式命名的旧 blob 有清楚区别。

仅支持未压缩 POSIX ustar。文件后缀不自动推断格式；不调用外部压缩器、shell、远端归档服务或本地 attributes。list 精确输出 `tar` 加 LF，须单独使用且不访问仓库。常规调用必须指定新输出文件，stdout 是 JSON 审计报告，不混入 tar 字节。

归档只含选中的常规文件，不暗加目录、链接、manifest 或可执行位。mode 0644、uid/gid/mtime 0 与空 owner 名称是固定**导出策略**，不是仓库存储的事实。格式使用 512 字节 header、八进制字段、标准 unsigned checksum、文件块 padding 和两个零结束块；在能够表示的斜线边界拆分 name[100]/prefix[155]。无法表示的名称或数值明确失败，不截断、不隐式生成扩展记录。文件内容不转换；UTF-8 文件名按字节保留，消费端需支持对应编码。

所有 header、长度与完整 JSON 报告先验证并构建，再复用现有独占导出接口发布新文件。不存在覆盖输出的选项；已存在文件、目录、链接、元数据路径或解析后进入 `.uwgit` 的父目录别名均明确拒绝。发布前失败不留下部分最终归档；发布后的同步、清理或报告写出失败可能保留完整目标文件，重试前应先检查目标，程序不会自动删除或覆盖它。

JSON 报告实际 object_id/kind/commit/tree、原 legacy anchor 与显式名称、每个成员的原路径/归档路径/原字节 SHA-256/长度，以及整个归档 SHA-256/长度与 metadata_policy。固定元数据使同一文件集合与前缀重复导出的 tar 字节完全相同；commit 与直接 tree 的 provenance 留在报告中，不混入用户模块集合。
