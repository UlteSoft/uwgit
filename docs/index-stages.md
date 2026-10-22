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
`--format` 支持 objectmode、objecttype、objectname、objectsize、stage、path，及 `%%`、ASCII `%xNN`；
objecttype 是真实的 wasm。未知字段或 modifier 拒绝，不生成 EOL/作者等不存在的信息。
它不能组合 stage/unmerged、others/killed、标签或 JSON 输出。

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
普通 restore 从未解决 index 读取该路径时要求明确选择一侧。
从指定的已提交树恢复暂存项可以直接替换 stages。

`merge-index` 使用 uwgit 的 Wasm 三方合并器，不调用外部 Git 程序。
必须给 `--all/-a` 或 `--` 后的 pathspec；可合成的路径进入 stage 0，仍有冲突的路径保留原图像。
目录/文件分歧不能被逐路径的成功结果掩盖。存在未解决项时退出 2，并报告各路径原因；
其他已解决的选中路径可以同时暂存。`--dry-run` 不修改 index。工作文件和 HEAD 始终保留。

status 明确标出未解决路径及现存 stage。commit、write-tree、stash push 和需要干净工作区的历史操作
拒绝未解决 index；当前 diff-files/diff-index/diff-worktree 也明确拒绝，尚未实现 combined diff。
clean 将未解决路径视为受控文件，不能当作 untracked 删除。

首次使用扩展字段时将 index 升级为 `UWGITIDX` 格式 3，解决后保留该版本；正常旧 index 格式 1/2 仍可读取。
老客户端不认识格式 3 时必须拒绝，不能丢弃 stages。不可变 Wasm/tree/commit 对象编码和 ID 不变。

本次 stages 由 read-tree 或 update-index 显式建立。`merge/cherry-pick/revert/rebase --record-conflict`
仍使用原有冻结 pending 记录，尚未自动将合并中间结果写入该索引扩展；其完整树审阅和显式续作合同保持。
索引 flags、intent-to-add、稀疏 index、ls-files 的 directory/abbrev/EOL/resolve-undo 等剩余选项仍见[能力矩阵](git-command-coverage.md)。
接口参考 [Git ls-files](https://git-scm.com/docs/git-ls-files) 与 [Git checkout-index](https://git-scm.com/docs/git-checkout-index)，对象及数据持久化继续使用 uwgit。

索引 version 4、assume/skip/图像有效性标志、intent-to-add 与 commit -a 见[原生索引标志](index-flags.md)。
已有 index 的 merge/pick/revert/rebase 录制及多目标 pick/revert 自动建立上述 stages，并带可恢复的工作区检查点；见[录制冲突](pending.md)、[rebase](rebase-pending.md)及[原生队列](replay-queue.md)。
