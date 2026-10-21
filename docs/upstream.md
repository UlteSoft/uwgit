# 分支 upstream 与默认远端工作流



## 行为与范围

- `branch DIR -u REMOTE/BRANCH [LOCAL]`、`--set-upstream-to SPEC`、`--set-upstream-to=SPEC` 设置已提交本地分支的已 fetch 目标；`--unset-upstream [LOCAL]` 取消。
- `branch DIR -vv` 输出稳定 JSON，列出本地分支、关联和真实 fetched tip；目标未 fetch 或消失时显示 gone，不用 HEAD 代替。
- `rev-parse DIR '@{u}'` / `'@{upstream}'`、`NAME@{u}` / `NAME@{upstream}` 查询实际 fetched tip；无关联或 gone 时明确失败。
- 默认 pull 采用关联 remote/branch；显式同一 remote 仍使用关联分支，显式其他 remote 使用本地同名分支，显式 BRANCH 覆盖两者。没有关联时保留 origin/本地同名回退。
- 默认 push 采用关联 remote；隐式目标遵循 simple 同名保护。与 upstream 使用同一 remote 且两端分支异名时，`push` 和 `push -u` 都要求明确的 `SOURCE:DESTINATION`。显式其他 remote 可以推当前同名分支。
- `push -u` / `--set-upstream` 仅用于单个已提交本地分支，远端精确确认后才保存关联。再次检查 remote 身份、本地 tip 及原关联；远端已发布但本地 CAS 或 I/O 失败时明确报告，不能把它当作未发送。
- 网络 clone 为已提交初始 HEAD 建立 origin 同名关联；空仓库没有关联。普通 branch/switch 不推断 tracking，本地 clone/bundle 不复制 upstream。
- 分支重命名移动关联，删除先清关联；remote rename 移动关联，remote remove 清关联，避免名称复用继承旧配置。服务端删除分支同样清理本地关联。

关联独立保存为 `.uwgit/upstreams.json` 的规范 version 1 数据，限制 1 MiB，拒绝重复键、非规范编码、未知字段、不合法名称、symlink 和孤立本地分支映射。
它不改变提交、RepositoryState、bundle 或网络协议格式。逻辑检查在对象安装和引用发布前完成；多文件 I/O 失败按已完成与不确定步骤报告，不承诺跨文件回滚。
push 不把远端广告伪装成 fetched tracking；新目标需 fetch 后才能通过 upstream 别名查询。

尚不支持 detached/orphan HEAD、自动 tracking 推断、push.default/pushRemote 配置或签名。冲突续作见 [单目标续作](pending.md) 与 [rebase 续作](rebase-pending.md)。
`branch -d` 仍按是否并入 HEAD 判断，与 Git 的 upstream 优先判断有差异。upstream 别名只在 rev-parse 的独立表达式入口支持，不接续 ancestry 或 reflog 语法。
全部命令差异继续列在[能力矩阵](git-command-coverage.md)，使用示例见[工作流](git-workflows.md)。
