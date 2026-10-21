# 真实靶机浏览器验收

`web/e2e/` 下的 Playwright 脚本覆盖三条核心旅程：资产 → 自动综合扫描 → 结果详情、总览 → 漏洞列表 → 指定发现项详情、定时/报告页面的 Server-backed 生命周期。它们不创建演示账号、不写入默认目标、不启动靶机，也不会扩大端口范围；所有凭据和目标都从本地环境变量读取。

## 前置条件

- 已在隔离靶机环境启动平台，并确认 Worker、规则库和 SSH 配置处于可用状态。
- 已有一个可以登录平台的测试账号；脚本不会创建账号。
- `SCANNER_E2E_TARGET_IP` 是明确授权的单个数字 IP，不能填写域名、CIDR 或网段。
- `SCANNER_E2E_PORT_RANGES` 是这次授权的端口或范围，例如 `12222,18080`；脚本会在提交前再次校验 1–65535。
- `SCANNER_E2E_CONFIRM=authorized` 是人为确认开关；`LAB_ENV=isolated` 是实验环境门槛。

## 运行

平台已运行在本机 `8080` 时，可按实际值执行：

```bash
LAB_ENV=isolated \
SCANNER_E2E_CONFIRM=authorized \
SCANNER_E2E_BASE_URL=http://127.0.0.1:8080 \
SCANNER_E2E_USERNAME='已有测试账号' \
SCANNER_E2E_PASSWORD='已有测试账号密码' \
SCANNER_E2E_TARGET_IP='<已授权的数字 IP>' \
SCANNER_E2E_PORT_RANGES='12222,18080' \
make test-browser
```

测试会在页面上登记资产（若清册中还没有该 IP），创建自动综合扫描，完成授权确认，等待任务进入“已完成”，再打开任务详情检查目标、开放端口和只读日志。任务和资产会保留，便于复核；如需清理，请在平台页面按正常归档/删除规则处理。

## 其余两条旅程

- `disposition-dashboard.spec.mjs` 打开总览的下钻链接，确认漏洞列表接收真实 Server 数据和筛选控件；设置 `SCANNER_E2E_FINDING_ID` 后，会从已认证的发现项集合中选取一项，只读打开详情抽屉，不修改状态、指派或备注。
- `schedule-report.spec.mjs` 确认定时任务和报告历史页面可达；设置 `SCANNER_E2E_TASK_ID` 后，会从已认证任务集合中选择一条任务，验证报告范围选择，不自动提交生成任务。

三份脚本共 5 个测试，`npm --prefix web run test:e2e -- --list` 可在不连接 Server 的情况下检查清单。没有 `SCANNER_E2E_FINDING_ID` 或 `SCANNER_E2E_TASK_ID` 时，相应的深入检查会跳过；完整实跑仍需通过 `make test-browser` 在隔离靶机上执行。

## PostgreSQL 隔离回归记录

2026-10-21 已在临时 PostgreSQL 数据库和隔离靶机上运行完整五条浏览器用例并全部通过。临时账号、资产、范围审批、任务和发现项在回归结束后清理；仓库不保存目标地址、密钥或扫描明细。该结果证明 PostgreSQL 模式下的资产登记、授权、自动综合扫描、SSH/Trivy/Nuclei 结果展示、总览下钻、发现项只读详情以及定时/报告页面可以贯通。批量漏洞处置/指派的浏览器写入操作、发布级范围抓包和完整节点生命周期仍需单独验收。

## 结果解释

- 失败在登录或资产登记：先检查 Server 地址、账号和数字 IP 校验。
- 任务保持 `PENDING`：检查节点状态、规则库 `CURRENT` 和 Worker 日志。
- 任务 `FAILED`：查看任务详情的安全错误、`runtime/worker.log` 和对应 `runtime/worker/scan-*` 日志；脚本不会把失败当作“无漏洞”。
- 任务完成但开放端口为零：说明靶机在所授权范围内没有响应的 TCP 服务，不能据此推断系统安全。

该验收只验证浏览器核心旅程和服务端保存的扫描结果；SSH 系统包、Trivy、Nuclei 规则命中仍需结合任务详情和 Worker 日志按测试方案分别核对。
