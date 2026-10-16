# 给 Codex 的任务指令:拆分 PR #1

> 使用前提:`AGENTS.md` 已合并"补充条款"(第 9–13 节)。把下面"指令正文"整体交给 Codex。
> 人工先完成:开启要求 PR 评审与 CI 的 `main` 分支保护、添加 `CODEOWNERS`,并处理下列规则冲突(见本文末尾"人工前置清单")。
> 可见性临时例外(2026-10-16,人工明确授权):当前暂时继续使用 Public,不以切换 Private 作为本次工作的前置条件;不得自行修改可见性,保密要求仍然有效。

---

## 指令正文

### 背景

当前有一个 Draft PR #1(分支 `feat/poc02-lease-gc-guards`,3 个提交:`bd63f2e`、`5957c04`、`f70698a`)。它把不同性质的改动混在了一起:

- 租约与 GC、`CURRENT` 指针(安全关键,需要人工逐行评审)
- API 脚手架、OpenAPI 合约、`bootstrap`、`repo` 接口契约、`cmd/*` 入口、portable 入口
- `web/` 前端工程
- CI 与 Makefile 改动

这违反了 `AGENTS.md` 第 28–30 条(一个 PR 一个任务、安全关键目录不得与其他目录混合、描述必须与 diff 一致)。另外 PR 描述说"`CURRENT` 原子指针切换尚未实现",但文件列表里已出现 `current_pointer.go`、`current_replace_windows.go`、`current_retry.go` 及测试。

### 你的任务

把 PR #1 **无语义变更地拆分**为三个 Draft PR。三个新 PR 创建后保留 PR #1 打开,只有人工明确确认可以关闭后才关闭。

**不要**:新增功能、修改业务逻辑、顺手重构、对现有分支执行 force push、合并任何 PR、修改 `AGENTS.md`。

### 执行门禁与待人工决策

- 本文是拆分方案,不自动豁免 `AGENTS.md` 的硬规则。补充条款尚未由人工合并时,只做盘点与方案整理,不开始代码拆分。
- 第 29 条与下述 PR B(含 `cmd/worker` 入口及其他目录)、PR C(含需人工评审的工作流、依赖文件及其他前端文件)存在范围冲突。必须由人工明确本次范围例外,或调整 PR 边界并更新本文后再执行,不得自行解释为已获豁免。
- 第 38 条要求 `docs/api/openapi.yaml`、`internal/api/dto.go`、`web/src/types` 在同一个 PR 中更新,而当前 B/C 分别包含前两者与后者。堆叠 PR 不能满足“同一个 PR”;必须由人工决定调整归属或明确本次例外后再执行。
- PR C 将已有前端工程与工作流放在一起,须确认第 45 条的“CI 脚手架首次建立”例外是否适用;不适用时由人工决定另拆 CI PR。不得为了固定三个 PR 而默许违反规则。
- `cmd/portable` 暂按原样列入 PR B,不扩展;是否保留尚待人工决定。前端已有页面的提前实现也不代表 Phase 0 计划已调整。

### 步骤

**第 0 步:盘点**
1. 拉取远端状态,记录最新 `origin/main`、PR #1 head 和二者 merge-base 的完整 SHA,作为本次拆分的固定基线。当前盘点的源 head 为 `f70698a3ff6ebe989fc9d4699f8a9c2062043a0b`,merge-base 为 `28c5d09b2a2f00fd5ca249256457d4035fbafd73`;执行时如源 head 已变化,先重新盘点。不要用会移动的 `main` 反复重算完整性基线。
2. 用 `git log --stat <固定merge-base>..<固定源head>` 逐个提交列出文件清单,确认每个文件来自哪个提交。保护原工作区的未提交文件,不得把本地计划或文档修改混入代码拆分。
3. 把全部改动文件按下面三类归属,输出一张"文件/片段 → 目标 PR"的对照表。当前源 diff 共 55 个文件;共享文件按下表逐片段分配。无法归类的文件先停下并向我提问,不要自行决定。

| 共享文件 | 目标 PR 与片段 |
| --- | --- |
| `Makefile` | B:增加 portable 编译的行;C:前端 `.PHONY` 与 `web-*` 目标。 |
| `README.md` | B:启动/API/portable 骨架说明;C:前端目录、演示页、前端 CI 与发布静态资产说明。混合段落按内容拆分。 |
| `docs/verification-log.md` | A:PoC #2 两条记录;B:四入口/API 记录;C:UI/前端发布记录。混合 API/前端记录按内容拆开,保留未验证事项。 |

独立的补充条款 PR 以及执行时新写的校验记录不属于原 PR #1 的 55 个文件,必须单独列明,不得伪装成源 diff。规则文件、校验记录与代码拆分的差异需要分别核对。

**第 1 步:PR A —— 租约、GC、`CURRENT` 指针(安全关键)**
- 分支:`feat/poc02-lease-gc-current`,基于最新 `main`。
- 只包含:
  - `internal/scheduler/lease_guard.go`、`lease_guard_test.go`
  - `internal/versionmgr/` 下全部文件(`current_pointer*`、`current_replace*`、`current_retry.go`、`gc_policy*` 及其测试与 Fuzz)
  - `pocs/02/README.md`
  - `docs/verification-log.md` 中与 PoC #2 相关的条目
- 不得包含:`web/`、`internal/api`、`internal/bootstrap`、`internal/repo`、`cmd/*`、`.github/`、`Makefile`、`README.md` 的非 PoC #2 内容。
- 如果 `scheduler` 或 `versionmgr` 对 `repo`、`api`、`bootstrap` 有依赖导致无法独立编译:**不要把那些文件拉进来**。改为在包内定义最小接口,并在汇报里说明这是为了拆分而做的最小调整。
- 必须独立通过 `make build`、`make lint`、`make test`,以及 `go test -race -count=5 ./internal/scheduler ./internal/versionmgr`。

**第 2 步:PR B —— API 与启动脚手架**
- 分支:`feat/api-contract-scaffold`。
- 包含:`internal/api/*`、`internal/bootstrap/*`、`internal/repo/contracts.go`、`cmd/server`、`cmd/updater`、`cmd/worker`、`cmd/portable` 的入口文件与说明、`docs/api/*`、`docs/scaffold.md`,以及上表分给 B 的 `Makefile`、`README.md`、`docs/verification-log.md` 片段。`web/src/types` 的归属须先按第 38 条解决执行门禁中的冲突。
- `cmd/portable` 属于计划外的提前内容。保留现状,**不得扩展**,并在 PR 描述中明确标注"计划外,请人工决定是否保留"。
- 必须独立通过 `make build`、`make lint`、`make test`。

**第 3 步:PR C —— 前端工程与 CI**
- 分支:`feat/web-console-scaffold`。
- 包含:`web/**`(其中 `web/src/types` 先解决第 38 条冲突)、`Makefile` 中的前端目标、`.gitignore` 中的前端条目、`.github/workflows/ci.yml` 与 `.github/workflows/build-artifacts.yml` 的前端构建、静态资产打包及相关校验片段,以及上表分给 C 的 `README.md`、`docs/verification-log.md` 片段。不能只搬新增 Job 而遗漏已有 Job 内的前端改动。
- 在这个 PR 里允许做以下**必要的合规调整**,并在描述中逐项列出:
  1. `Makefile` 的 `web-install` 由 `npm install` 改为 `npm ci`(`AGENTS.md` 第 35 条)。
  2. 工作流中的第三方 Action 固定到提交哈希并注明版本(第 40 条)。
  3. CI 中安装依赖时禁用安装脚本,如确需运行脚本请单独说明(第 35 条)。
  4. 为 `web/` 的依赖增加许可证与漏洞扫描步骤的方案说明;若本 PR 无法落地,在描述的"未实现"中明确列出。
  未实现依赖扫描时只可保持 Draft,方案说明不等于满足第 39 条合并门禁。不得顺手更新依赖版本。
- 必须独立通过 `make build`、`make lint`、`make test`,以及前端 CI(`npm ci --ignore-scripts`、类型检查、演示与 Server 两种模式的构建)。确需安装脚本时先说明原因并获批准。

**第 4 步:顺序与依赖**
- 合并顺序:A → B → C。PR A 必须能独立基于 `main` 合并。
- 如果 B 依赖 A、或 C 依赖 B,在描述里写明依赖,并优先通过调整内容使其互相独立;确需堆叠时使用以前一个分支为 base 的方式,并说明。

**第 5 步:完整性校验(必须执行并附输出)**
1. 三个 PR 搬运的文件集合并集,必须**等于** `git diff --name-only <固定merge-base> <固定源head>` 的文件集合:不遗漏、不新增。合规调整、必要的最小接口调整与新的验证记录另列清单,说明原因;共享文件允许出现在多个 PR 中,但片段不得重复搬运或遗漏。堆叠 PR 的文件集合只按各自 base 到 head 的 diff 计算,不得重复计算继承内容。
2. 对 A、B 中整文件原样搬运的文件,逐一执行 `git diff <固定源head> <目标head> -- <文件>` 并确认输出为空。共享文件不适用单 PR 整文件相等检查,须逐片段比对;A 的最小接口调整须单独列出 diff。
3. 在临时集成分支按 A → B → C 合成最终树,将上述源文件逐一与固定源 head 比较。除已列明的合规调整、最小接口调整及为准确记录而更新的说明外,差异必须为空。仅比较文件名不能证明内容完整。
4. 每个 PR 单独运行验证命令并贴出输出摘要;不得把原分支或临时集成分支上的测试当作各 PR 已通过的证据。原记录中的“CURRENT 尚未实现”等陈旧描述需据实际代码修正,并列入非纯搬运清单。

**第 6 步:PR 描述**
每个 PR 严格按 `AGENTS.md` 第 9.3 节的模板填写。PR A 额外增加"评审重点"一节,针对下列问题逐条给出**结论和文件:行号**(不知道或没实现就如实写"未实现"):
1. 租约到期的本地判断是否使用单调时钟?`hard_deadline` 中依赖墙上时间的部分是否单独说明?
2. Worker 本地"失联自终止"阈值是否小于 Server 的租约时长,并预留了时钟偏差余量?
3. 返回"终止未确认"(`ErrWorkerStopTimeout`)之后,是否强制终止整个进程树?(未实现请注明,不得声称已有。)
4. 续约失败是否保证不延长最后确认的到期时间?
5. Server 端是否拒绝把新租约绑定到已退役版本?(属于 Server 实现,当前是否已覆盖。)
6. 版本号比较是否按数值而非字符串字典序?`20261016.10` 与 `20261016.02` 的比较有无测试?
7. `CURRENT` 读取遇到空文件或半写内容时是否重试?
8. `CURRENT` 写入后是否对所在目录执行了 fsync(POSIX)?Windows 的替换失败重试是否有上限和退避?
9. GC 的宽限期下限(不少于 2 小时)能否通过配置被绕过?
10. GC 无法向 Server 确认时是否一律拒绝回收(失败即关闭)?
11. 实际删除目前是否仍被禁用?将来实现时,路径越界(`..`)、符号链接、TOCTOU 将如何防护?(当前未实现则写明。)

**第 7 步:收尾**
- 三个新 PR 都创建为 **Draft**。
- 在 PR #1 中留言,列出三个新 PR 的链接和对应关系,**但先不要关闭**,等我确认后再关闭。
- 不要删除原分支。

### 汇报格式

按 `AGENTS.md` 第 13 节的模板汇报,并附:
- "文件 → 目标 PR"对照表。
- 第 5 步完整性校验的输出。
- 你在拆分过程中做的所有**非纯搬运的改动**清单(没有则写"无")。
- 发现的其他问题清单(**只记录,不要修复**)。

---

## 人工前置清单(不属于 Codex)

在把指令交给 Codex 之前,请先完成:

1. **当前暂时保留 Public**(2026-10-16,人工明确授权)。不修改仓库可见性;何时恢复 Private 待人工决定。仍需检查 `docs/` 和提交历史中是否有内部地址、人名、工单号。
2. **开启 `main` 分支保护**:禁止直接推送、要求 PR 评审、要求 CI 通过。只有禁止删除/force push 的 ruleset 不满足这些要求。
3. **添加 `CODEOWNERS`**,把以下路径设为必须由你(或指定人员)评审:
   ```text
   /internal/versionmgr/   @你的账号
   /internal/scope/        @你的账号
   /internal/executor/     @你的账号
   /internal/scheduler/    @你的账号
   /internal/api/          @你的账号
   /cmd/worker/            @你的账号
   /.github/workflows/     @你的账号
   /go.mod                 @你的账号
   /go.sum                 @你的账号
   /web/package.json       @你的账号
   /web/package-lock.json  @你的账号
   ```
4. 将 `AGENTS-addendum.md` 的“对 8.3 的补充”合入原第 8.3 节,只把第 9–13 节追加到 `AGENTS.md` 末尾,以独立文档 PR 由人工合并。拆分执行器不得合并该 PR。
5. 明确执行门禁中第 29、38、45 条与三 PR 方案的冲突如何处理,再更新本文。`docs/dev-plan-daily.md` 随独立文档 PR #2 纳入版本控制,属于待人工确认的计划;不要把它重复混入代码拆分。
6. 合并顺序确认后,再评审 PR A(重点);PR B、PR C 可以排在后面。`cmd/portable` 是否保留以及何时关闭 PR #1 仍须人工明确决定,不得根据本文件推定已批准。
