# 原生索引标志与 intent-to-add

这些入口直接操作 uwgit 的完整 Wasm 原字节索引；不调用 Git，也不创建 Git blob、stat cache 或外部监控进程。
新编码 `UWGITIDX` version 4 在原有文件图像、legacy 路径和冲突 stages 之外保存路径标志与无图像的意向条目。
旧 version 1/2/3 继续可读；只有需要新字段时升级。清除最后一个标志仍保留合法的 version 4，避免悄悄降级。
保存冲突解决的原侧时升级为 version 5，标志及意向条目继续有效，后续修改不降级；见[索引撤回记录](index-stages.md#解决记录与索引撤回)。

```sh
wasm-git update-index DIR --assume-unchanged modules/a.wasm
wasm-git update-index DIR --no-assume-unchanged modules/a.wasm
wasm-git update-index DIR --skip-worktree modules/large.wasm
wasm-git update-index DIR --no-skip-worktree modules/large.wasm
wasm-git update-index DIR --fsmonitor-valid modules/a.wasm
wasm-git update-index DIR --no-fsmonitor-valid modules/a.wasm
wasm-git update-index DIR --refresh
wasm-git update-index DIR --really-refresh --ignore-missing --unmerged
printf 'modules/a.wasm\0' | wasm-git update-index DIR --assume-unchanged --stdin -z
wasm-git ls-files DIR -v
wasm-git ls-files DIR -f
```

标志修改要求明确的精确路径，可以组合多种位修改；与 `--add/--remove/--cacheinfo/--index-info` 等内容更新模式互斥。
整批先验证再一次写入，后面的非法路径不会留下前面条目的部分修改。未解决 stages 不能设置标志。

| 标志 | 实际行为 |
|---|---|
| assume-unchanged | status、工作区 diff、ls-files 修改筛选使用已暂存图像；add/commit -a 不读取该路径的新内容。更改实际文件不表示自动暂存。历史写操作仍核对真实字节，不允许这个查询承诺造成数据丢失。 |
| skip-worktree | 同样保留索引承诺；缺席工作文件不会被普通 add、checkout-index、restore、switch 或 hard reset 自动物化。普通批量 add 跳过；只选择跳过路径的 add 要求显式 `--sparse`。 |
| fsmonitor-valid | 记录已核对的原图像 SHA-256；只有当前工作字节仍等于该图像时，查询才报告有效。修改后立即失效，不依赖 mtime。这里没有外部 FSMonitor 协议或后台守护进程。 |

`--refresh` 比较字节而不暂存，普通 refresh 跳过 assume/skip 承诺，`--really-refresh` 检查这些路径。
任一不匹配都失败，保留整个原 index。`--ignore-missing` 允许工作侧缺席；`--unmerged` 跳过未解决项。
这两个修饰符要求 refresh。没有实际元数据变化时保留原编码。

`ls-files -t` 对 skip 条目输出 `S`；`-v` 将 assume 条目标签转小写，`-f` 将当前有效图像标签转小写。
JSON 提供 `assume_unchanged`、`skip_worktree`、`fsmonitor_valid` 和 `intent_to_add`。

```sh
wasm-git checkout-index DIR --all --ignore-skip-worktree-bits
wasm-git restore DIR --ignore-skip-worktree-bits -- modules/large.wasm
wasm-git add DIR --sparse modules/large.wasm
```

显式覆盖 skip 的物化仍遵守对应命令的覆盖与 untracked 保护。restore 的 staged 更新、分支切换和 reset 将标志继承给仍存在的路径；
图像变化会清除原 fsmonitor 摘要。mv 搬移对应条目标志，rm 清除被移除路径的标志。
stash 保存真实受控工作字节与索引标志；跳过文件的原本缺席可以恢复。

## 只记录新增意向

```sh
wasm-git add DIR -N modules/new.wasm
wasm-git ls-files DIR -s
wasm-git diff-files DIR --name-status
wasm-git commit DIR -a -m 'stage actual controlled images'
```

`-N/--intent-to-add` 验证新路径是实际 Wasm 后只记名字，不保存图像、不安装对象。
`ls-files -s` 显示 `100644 - 0<TAB>PATH`，JSON 的 object_id 为 null，格式字段 objecttype 为 `intent`。
这里的 `-` 表示不存在对象，不能拿它查询对象；不会用空 Wasm 伪造 Git 的 empty blob。

status 将它报告为工作侧新增，diff-files 可报告 `A`；它不会进入 write-tree 或普通 commit。
再次 add 会暂存当时的实际原字节。`commit -a/--all` 暂存受控文件与意向路径的实际新增、修改和缺席，保留未受控文件。
mv 可搬移意向条目与任意尚未暂存的编辑字节；rm --cached 取消意向并保留工作文件。
没有可恢复图像时普通 restore 拒绝；stash 与 replay 要求先完成或移除意向条目，避免丢失未保存的来源。

## 验证与边界

固定测试位于 [index_flags_cli.rs](../tests/index_flags_cli.rs)，覆盖版本保留、批量失败保持、NUL 输入、隐藏修改保护、
稀疏缺席、显式物化、意向条目移动/删除、提交树成员、刷新与摘要失效；独立真实 Git 仓库对照标签与意向成员规则。
这些标志不等于完整 sparse-checkout、sparse-index、split-index、untracked cache、外部 FSMonitor 或 chmod 位支持。
stages 和内容 plumbing 见[索引契约](index-stages.md)，后续项目见[能力矩阵](git-command-coverage.md)。
