# 原生索引、冲突 stages 与底层更新

索引保存逻辑路径和原始 Core Wasm 字节，不保存 Git blob、Unix mode 或 Git index 二进制。
正常条目是 stage 0；未解决路径可分别保存 stage 1（base）、2（ours）、3（theirs）。
缺席的一侧没有条目，不能用空文件或生成的空 Wasm 模块代替。

```sh
wasm-git read-tree DIR TREE_OR_COMMIT
wasm-git read-tree DIR --empty
wasm-git read-tree DIR -m BASE OURS THEIRS
wasm-git read-tree DIR -m BASE THEIRS
wasm-git ls-files DIR --stage -z -- 'modules/*.wasm'
wasm-git ls-files DIR --unmerged
wasm-git ls-files DIR --json
wasm-git write-tree DIR --prefix modules/
```

普通 `read-tree` 只替换 index，不移动 HEAD，不修改工作文件。`-m` 对路径做三方比较：
两侧相等，或者只有一侧相对 base 改变时，保存确定结果；其余情况保存各侧的实际字节。
两棵树形式将当前完整且没有冲突的 index 作为 ours。这是明确的 uwgit 语义，
并不声称等同 Git 两树 read-tree 对暂存变更的全部携带规则。
read-tree 不在文件内部自动合成代码；需要文件内合并时可再使用 `merge-index`。

文件与目录的冲突会保留相关路径的原始 stages，例如 ours 的 `module` 和 theirs 的
`module/child.wasm`。每一个 stage 与已解决条目的组合必须仍是合法的平面文件树；
同一 stage 不能同时有文件及其子路径。不同 stage 可以表达真实的目录/文件分歧。

`--prefix DIR/` 将一棵命名树导入现有已解决 index 的新目录；已有路径及前缀碰撞全部拒绝。
旧未命名模块不能由 read-tree 猜测文件名，须先显式建立路径。不同 legacy 路径身份不能混合。
`-n/--dry-run` 完成验证后只报告。`-u/--update` 同时物化结果，未解决项使用 ours 的原字节：
目标没有改变的工作路径保留脏字节；目标改变且会覆盖脏字节时整次拒绝。
untracked 文件、符号链接和特殊文件继续受到完整预检保护。多文件 I/O 失败会报告已完成范围，
不承诺工作树与 index 跨文件断电事务。

`ls-files` 默认列出 index 路径，未解决路径会按现存 stage 分别列出。
`-s/--stage` 输出 `100644 NATIVE_ID STAGE<TAB>PATH`，`-u/--unmerged` 只输出未解决 stages 并隐含 stage 格式。
`-c/--cached` 明确选择默认来源。`-z` 使用 NUL 分隔；`--json` 给出路径、stage、原生对象 ID 和字节长度。
100644 是普通 Wasm 文件的输出约定，不是已保存的文件 mode。
原生 ID 根据 index 内的字节计算，暂存本身未必已将对应对象发布到对象库；JSON 明确标注这一点。
`write-tree --prefix DIR/` 只发布该 index 子目录，去掉路径前缀；不存在的目录在创建对象前拒绝。

## 列表筛选与格式

```sh
wasm-git ls-files DIR --modified --deleted --deduplicate
wasm-git ls-files DIR --others --exclude-standard
wasm-git ls-files DIR --others --ignored --exclude-standard
wasm-git ls-files DIR --killed -t
wasm-git ls-files DIR --format='%(objecttype) %(objectname) %(stage)%x09%(path)'
wasm-git ls-files DIR --others --directory --no-empty-directory --exclude-standard
wasm-git ls-files DIR --stage --abbrev=8
wasm-git ls-files DIR --with-tree HEAD --error-unmatch -- modules/removed.wasm
wasm-git ls-files DIR --eol
```

`-m/--modified` 比较工作原字节与对应 stage，删除也算修改；`-d/--deleted` 选择工作侧缺席的模块。
`-o/--others` 列出未受控的普通文件，包含非 Wasm 文件；`-k/--killed` 列出阻挡受控路径物化的
未受控文件/目录冲突项。扫描不进入元数据、嵌套仓库或符号链接。`-t` 为输出行加 H/M/R/C/?/K 原因标签。
多个来源或多个 stages 可以产生重复路径；`--deduplicate` 在只列名称时按路径去重，不丢弃 stage 或标签信息。

`-i/--ignored` 需显式组合 `-c` 或 `-o`，并给出排除规则。
`--exclude-standard` 使用仓库内 `.gitignore` 和 `.uwgitignore`，不读取用户的全局 Git 配置。
另有可重复的 `-x/--exclude PATTERN`、`-X/--exclude-from FILE`、`--exclude-per-directory BASENAME`。
规则按目录范围和优先级匹配，也能正确识别已暂存但工作侧缺席的忽略路径；已排除的父目录不能由子目录规则重新纳入。
一个规则文件最多 1 MiB；错误规则与不可读输入均不改变 index。

列表查询默认允许没有匹配的选择器，以空结果表示；`--error-unmatch` 要求每个正向选择器在 index 内匹配。
这个只读查询合同不放宽 add/restore/read-tree 等写命令的严格选择规则。
`--format` 支持 objectmode、objecttype、objectname、objectsize、stage、path、eolinfo:index、eolinfo:worktree、eolattr，及 `%%`、ASCII `%xNN`；
objecttype 是真实的 wasm。未知字段或 modifier 拒绝，不生成作者等未保存的信息。
它不能组合 stage/unmerged、others/killed、resolve-undo、eol、标签或 JSON 输出。

### 目录、唯一缩写与历史树视图

`--others --directory` 将整体未受控、符合当前选择和忽略规则的目录折叠为带末尾 `/` 的一行。
已暂存、intent 或未解决路径占用的目录不会整层折叠，但其未受控子目录可以折叠。
精确子文件或只匹配文件名的 glob 会继续列该文件；明确选择目录时可输出目录行。
精确路径查询不加载无关子目录的排除文件；目录折叠只加载判定所需子树的规则。
`--no-empty-directory` 只在 directory/others 组合中生效，省略没有符合当前选择和忽略类别的普通文件的目录。
默认允许空目录和只有忽略内容的未忽略目录，指定 exclude-standard 后仍保护已忽略父目录。
ignored 模式可折叠明确忽略的目录或全部可见文件都被忽略的目录，每个目录只输出一行；这与 Git 某些 ignored/directory 组合的重复行行为不同。
含未检查的嵌套仓库、symlink 或特殊文件时，祖先不折叠，继续列出可检查的普通文件；不跟随这些边界。
目录 JSON 标记 `directory: true`，没有对象 ID、stage 或 Wasm 图像；这些目录不是新建的树对象。

`--abbrev[=N]` 缩写 stage/resolve-undo 输出和 format 的 objectname。省略 N 时使用 12，范围 0..64；
非零最少 4 位，0 使用完整 64 位原生 ID。前缀在已验证对象库的所有对象种类和完整索引图像中唯一，
包括没有选中的 stages、resolve-undo 以及尚未发布的 stage 0；重复图像不制造歧义。
发生碰撞时自动延长到可区分的最短长度，不为缩写发布对象。JSON 始终保留完整 object_id，并另给 object_abbrev。

`--with-tree REV` 从一次已验证的命名 commit/tree 视图补入当前 index 缺失的路径，支持修订解析和直接树 ID。
同名的真实 index 条目、flags、intent 或 conflict 优先；不保存新 index，不物化文件，不移动 HEAD。
error-unmatch 使用真实 index 与历史树路径的并集，未匹配仍在输出任何行前失败。
树补充项在 JSON 中标记 `source: "tree"`、`source_object`、`index_entry: false` 和 null stage，format 的 stage 为 `-`。
不同来源的文件/目录前缀可同时出现在这个查询视图中，不会成为可发布的冲突索引。
with-tree 与 stage/unmerged 互斥；旧未命名历史没有可猜测的路径，明确拒绝。

### 原字节 EOL 观察

`--eol` 为各普通来源行附上 `i/INDEX w/WORK attr/`；可与 stage、标签、NUL 或 JSON 组合。
format 的 `%(eolinfo:index)`、`%(eolinfo:worktree)` 和 `%(eolattr)` 提供同一观察；format 与 --eol 互斥。
原字节分为 `none`、`lf`、`crlf`、`mixed` 或二进制 `-text`，包含 NUL 的 Wasm 图像因此为 `-text`。
裸 CR 和较高比例的非文本控制字节也为 `-text`；文件末尾的 DOS EOF 不单独算二进制证据。
工作文件按流读取，跨块 CRLF 不拆开；不做转码、行尾规范化或模块重写。

EOL 始终观察真实工作文件，包含 assume/skip 路径上的脏字节。缺席、目录、symlink 或非普通工作侧为空；
symlink 父路径也不跟随。intent 没有索引图像，因此 i/ 为空；历史树补充项同样不伪装为索引内容。
resolve-undo 的文本行继续只显示真实 side/ID，不附工作侧 EOL。
uwgit 的 Wasm 模型没有文本转换属性：eolattr/attr 为空，`.gitattributes`、Git 全局配置及 autocrlf 不参与转换。
JSON 的 eol_index/eol_worktree/eol_attribute 和 eol_policy 明确给出这个范围；它不是属性或内容规范化实现。

只读回归见 [index_listing_cli.rs](../tests/index_listing_cli.rs)，包含完整失败保持、未发布/跨对象种类碰撞、边界目录、
历史树来源及原字节观察；[独立 Git 对照](../tests/git_reference_cli.rs) 覆盖普通目录折叠、选择器、原字节 EOL 与历史路径准入。

## 从索引物化及导出

```sh
wasm-git checkout-index DIR --all
wasm-git checkout-index DIR --force --no-create --all
wasm-git checkout-index DIR --all --prefix export/
printf 'modules/a.wasm\0' | wasm-git checkout-index DIR --stdin -z
wasm-git checkout-index DIR --stage=2 -- modules/a.wasm
wasm-git checkout-index DIR --stage=all --all -z
```

`checkout-index` 从实际 index 图像写出文件，不修改 index、HEAD 或引用。
无路径且未给 `--all/-a` 时不做事；`--` 后是精确路径而非 pathspec。
所有选择都预读后才进行写入，任一失败不先处理其他项。默认拒绝覆盖已有普通文件；`--force/-f` 明确覆盖，
`--no-create/-n` 只处理已存在的普通文件。`--quiet/-q` 跳过不存在的 index/stage 项或未授权覆盖的已有文件。
符号链接、特殊文件、`.git` 元数据路径和未选择的目录阻挡即便 force 也拒绝。`--prefix STRING` 按字面前缀构造根内目标，
既可写 `export/`，也可写 `.review-`；不能逃逸仓库。`--dry-run` 完整预检后仅输出计划。

`--stage=1|2|3` 选择真实冲突侧，缺席侧报错。`--temp` 将所选图像写入仓库根下独占创建的
`uwgit-index-PID-SEQUENCE.wasm`；`--stage=all` 隐含 temp，只导出未解决项。
输出为 `TEMP<TAB>PATH`，all 形式为 `BASE_TEMP OURS_TEMP THEIRS_TEMP<TAB>PATH`；
缺席侧用 `.`，`-z` 将记录分隔符改为 NUL。映射到的导出文件由调用者使用后移除；失败会清理本次已创建文件。
原工作文件和 index 保持原字节。本模型没有 stat cache，`-u/--index` 仍拒绝。默认尊重 skip-worktree，显式 `--ignore-skip-worktree-bits` 可物化；详见[索引标志](index-flags.md)。

## 直接更新

```sh
wasm-git update-index DIR --add modules/new.wasm
wasm-git update-index DIR --remove modules/missing.wasm
wasm-git update-index DIR --force-remove modules/keep-working-copy.wasm
wasm-git update-index DIR --add --cacheinfo 100644,OBJECT_ID,modules/cached.wasm
printf '100644 OBJECT_ID 1\tmodules/a.wasm\n' | wasm-git update-index DIR --index-info
printf 'modules/a.wasm\0modules/b.wasm\0' | wasm-git update-index DIR --stdin -z
```

工作路径形式读取原始 Wasm 文件；新路径需要 `--add`，缺失路径需要 `--remove`。
`--force-remove` 只移除 index 条目，保留工作文件。`--cacheinfo` 接受逗号形式或三个独立参数，
对象必须是实际存储的完整 64 位小写原生 Wasm ID；新路径仍需 `--add`。

`--index-info` 接受 `MODE ID<TAB>PATH`、`MODE TYPE ID<TAB>PATH`，以及带 `STAGE` 的对应形式。
TYPE 可以写 wasm 或 blob，但输入对象始终是原始 Wasm 对象。MODE 为 100644，STAGE 为 0..3；
MODE 为 0 则删除该路径全部 stages，不读取占位对象。stage 0 替换未解决项，
stage 1..3 替换该侧并清除同名 stage 0。输入按换行或 `-z` 的 NUL 分隔，最多 64 MiB。
整批记录、对象、路径和树结构都验证成功后，才一次发布 index。后续记录出错时，前面的记录也不落盘。
`--dry-run` 保留原 index。命令不创建提交、不移动 HEAD、不修改工作文件。

## 解决冲突

```sh
wasm-git restore DIR --ours -- modules/a.wasm
wasm-git checkout DIR --theirs -- modules/a.wasm
wasm-git add DIR modules/a.wasm
wasm-git rm DIR --force -- modules/deleted.wasm
wasm-git merge-index DIR --all --dry-run
wasm-git merge-index DIR --all
wasm-git write-tree DIR
```

restore/checkout 选择 stage 2 或 3，只修改显式选择的工作文件；缺席侧表示删除。
index 中原始 stages 保留，需再显式 add/rm 或 update-index 才算解决。
目录/文件转换应选择完整冲突组，例如 `-- .`；未选择路径的工作字节保持。
普通 restore 从未解决 index 读取该路径时要求显式选择冲突处理方式。
从指定的已提交树恢复暂存项可以直接替换 stages。

### 重建冲突工作副本

```sh
wasm-git restore DIR --merge -- modules/a.wasm
wasm-git checkout DIR -m -- modules/a.wasm
wasm-git restore DIR --ignore-unmerged -- .
wasm-git checkout DIR -m --ignore-skip-worktree-bits -- modules/a.wasm
```

`restore --merge/-m` 与 checkout 的显式路径模式 `--merge/-m -- PATHSPEC...` 从现有 index 重建合并工作文件。
已解决路径有 resolve-undo 时，先在内存恢复并消费所选原始 stages；没有撤回记录的 stage 0 按原图像恢复。
已处于 unmerged 的路径以当前 stages 为准，不被旧撤回记录替换。选择器共用 glob/literal/icase/top/exclude；
每个正选择器必须匹配，撤回记录也在 merge 模式的候选集合中。需要显式路径，不能从 source 修订、staged 或独占导出混用这些冲突选项。

冲突路径要求 stage 2 和 3 都存在；base 可以缺席。先使用原生 Wasm 三方合并器，能合成时物化经过校验的模块，
无法合成时保留 ours 的完整原始字节并在输出中逐路径报告原因。成功仅表示工作文件已重建：
包括成功合成的路径在内，原始 stages 都继续处于 unmerged，仍须审阅后 add/rm 才能提交。
原图像中的未知内容继续保留；不会向 Wasm 插入文本冲突标记。Git 的文本 conflict style 选项尚未实现。

缺少任一现存侧、无图像 intent、非法或未匹配选择器、索引/目录结构冲突及工作区障碍，均在写入前使整批失败。
文件/目录冲突通常没有同一路径的两个现存侧，merge 模式拒绝；可选完整冲突组后使用 ours/theirs 或显式树解决。
恢复已删除路径时，旧撤回记录不授予覆盖后来 untracked 文件的权限；需先移开该文件。
skip-worktree 路径默认连同撤回记录保持，`--ignore-skip-worktree-bits` 在 merge 模式显式恢复后才消费记录并移除其旧 flags。
HEAD、pending 队列、其他撤回记录和不可变对象不变；linked worktree 各自处理自己的索引。

ours/theirs 同时选择 stage 0 普通路径时按该原图像恢复。`restore --ignore-unmerged` 只恢复选中的普通路径，
保留 unmerged 路径的工作字节和 stages；不会从撤回记录重新建立冲突。工作文件恢复也可显式写 `--worktree/-W`。
上述命令沿用 index 锁、完整目标校验和工作区二次预检；发布 I/O 失败会报告已完成范围。
工作区与索引不承诺跨文件断电事务；工作文件已经恢复但索引保存失败时明确报告，撤回记录仍可用于重试。

接口参考 [Git restore](https://git-scm.com/docs/git-restore) 和 [Git checkout](https://git-scm.com/docs/git-checkout)。
Git 二进制回退、stages/撤回生命周期及缺失侧拒绝有独立对照；原生 Wasm 结构组合与批量失败保持另有专门回归。

`merge-index` 使用 uwgit 的 Wasm 三方合并器，不调用外部 Git 程序。
必须给 `--all/-a` 或 `--` 后的 pathspec；可合成的路径进入 stage 0，仍有冲突的路径保留原图像。
目录/文件分歧不能被逐路径的成功结果掩盖。存在未解决项时退出 2，并报告各路径原因；
其他已解决的选中路径可以同时暂存。`--dry-run` 不修改 index。工作文件和 HEAD 始终保留。

status 明确标出未解决路径及现存 stage。commit、write-tree、stash push 和需要干净工作区的历史操作
拒绝未解决 index；当前 diff-files/diff-index/diff-worktree 也明确拒绝，尚未实现 combined diff。
clean 将未解决路径视为受控文件，不能当作 untracked 删除。

首次保存 stages 时 index 至少为 `UWGITIDX` 格式 3；解决路径生成撤回记录时升级为格式 5。正常旧 index 格式 1/2 仍可读取。
老客户端不认识格式 3 时必须拒绝，不能丢弃 stages。不可变 Wasm/tree/commit 对象编码和 ID 不变。

stages 可由 read-tree、update-index 或录制的 merge/pick/revert/rebase 队列建立。
索引 flags、intent-to-add 见[索引标志](index-flags.md)；稀疏 index、Git 属性转换和其他剩余选项仍见[能力矩阵](git-command-coverage.md)。
接口参考 [Git ls-files](https://git-scm.com/docs/git-ls-files) 与 [Git checkout-index](https://git-scm.com/docs/git-checkout-index)，对象及数据持久化继续使用 uwgit。

索引 version 4、assume/skip/图像有效性标志、intent-to-add 与 commit -a 见[原生索引标志](index-flags.md)。
已有 index 的 merge/pick/revert/rebase 录制及多目标 pick/revert 自动建立上述 stages，并带可恢复的工作区检查点；见[录制冲突](pending.md)、[rebase](rebase-pending.md)及[原生队列](replay-queue.md)。

## 解决记录与索引撤回

```sh
wasm-git add DIR modules/a.wasm
wasm-git ls-files DIR --resolve-undo
wasm-git ls-files DIR --resolve-undo --json
wasm-git update-index DIR --unresolve modules/a.wasm
wasm-git restore DIR --ours -- modules/a.wasm
printf 'modules/a.wasm\0' | wasm-git update-index DIR --unresolve --stdin -z
wasm-git update-index DIR --clear-resolve-undo
```

解决未合并路径时，索引 version 5 的 `resolve_undo` 保存移除前完整 stage 1/2/3 的原始 Wasm 字节。
add、rm、update-index 的工作路径/cacheinfo/index-info、staged restore、merge-index 和 mergetool 暂存均使用同一规则。
删除解决也保留原侧；原来不存在的一侧仍为 null。普通 stage 0 修改不会替换上一次保存的冲突。
预检错误或 dry-run 不生成撤回记录，也不先发布前面的批量修改；merge-index 仍可在退出 2 时保留本次成功解决的路径。

`ls-files --resolve-undo` 默认只列撤回记录，每个现存侧输出 `100644 NATIVE_ID STAGE<TAB>PATH`。
`-t/-v/-f` 的记录标签为 `U`；`-z`、路径选择器可用，`--deduplicate` 不折叠这些 stages。
显式 cached/stage 等来源仍可同时查询，普通来源先于撤回记录输出。
JSON 的记录含 `resolve_undo: true`、`reason: "U"` 和真实原生 ID；该 ID 所指图像可能只存在于 index 中。
撤回记录不继承当前 stage 0 的 assume/skip/fsmonitor/intent 标志。没有 `--resolve-undo` 时，旧列表行为不变。

`update-index --unresolve` 使用精确路径，或 `--stdin [-z]` 的精确路径列表。
整批先验证，移除所选 stage 0/intent/标志，再重建已保存的原侧并消费对应撤回记录。
已经 unmerged 的路径保持现有 sides；没有记录的合法路径和空列表不做修改。
它只改 index，不移动 HEAD、不写工作文件、不安装对象，也不从当前 HEAD 或 pending 猜测丢失的侧。
随后可显式 restore --ours/--theirs 或再次编辑、add/rm；未解决状态重新阻止 write-tree、commit 和 replay continue。
需同时重建工作文件时，可用上述 checkout -m/restore --merge 入口；它保留未解决状态，直到显式审定暂存。

文件/目录组必须选出足以组成合法完整 index 的路径集合。单独撤回父路径会与已解决子路径碰撞时，整批拒绝；
一起选择相关父子路径可以恢复真实的跨 stage 分歧。不同历史步骤的撤回记录不必彼此构成同一棵树。
`--clear-resolve-undo` 只清除全部撤回记录，保留现存 stages、文件图像、标志和工作副本。
两个控制与内容更新/refresh/标志修改互斥；clear 不接受路径或 stdin。两者都支持 dry-run、遵守 index 锁。

version 1/2/3/4 索引继续可读，原编码没有新增空字段；第一次保存撤回记录时升级为 `UWGITIDX\x05`。
清除最后一个记录后保留 version 5，后续标志修改不能降级或丢记录。索引元数据与图像通过同一次 canonical 写入发布。
未知字段、错误 magic/version、非法路径、空记录或非 Wasm 原侧均拒绝。不可变 Wasm/tree/commit 编码和 ID 不变。

完整 read-tree、switch、mixed/hard reset 等整树替换建立新的 index 并清除旧撤回记录；read-tree prefix 保留现有记录。
普通 commit 保留 index，stash 保存并恢复记录。linked worktree 的记录各自独立。
replay continue/skip 的检查点保留当时的记录并验证它与原 index 一致；skip 允许修复损坏 index 时无法恢复已损坏的撤回信息。
abort 恢复原 index 的完整原编码，包含原来的 version 5 记录。撤回记录只描述保存的历史 sides，不表示当前步骤仍然 pending。

回归见 [index_resolve_undo_cli.rs](../tests/index_resolve_undo_cli.rs)、
[编码与校验](../src/index_resolve_undo.rs)、[检查点恢复](../src/porcelain_replay.rs) 和独立 [Git 对照](../tests/git_reference_cli.rs)。
选项参考 [Git update-index](https://git-scm.com/docs/git-update-index)、[Git ls-files](https://git-scm.com/docs/git-ls-files)；
这里继续使用原生 Wasm 编码、原图像校验与批量失败保持合同。
