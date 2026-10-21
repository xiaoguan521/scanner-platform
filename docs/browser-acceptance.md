# 真实靶机浏览器验收

`web/e2e/core-journey.spec.mjs` 是核心“资产 → 自动综合扫描 → 结果详情”浏览器验收。它不创建演示账号、不写入默认目标、不启动靶机，也不会扩大端口范围；所有凭据和目标都从本地环境变量读取。

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

## 结果解释

- 失败在登录或资产登记：先检查 Server 地址、账号和数字 IP 校验。
- 任务保持 `PENDING`：检查节点状态、规则库 `CURRENT` 和 Worker 日志。
- 任务 `FAILED`：查看任务详情的安全错误、`runtime/worker.log` 和对应 `runtime/worker/scan-*` 日志；脚本不会把失败当作“无漏洞”。
- 任务完成但开放端口为零：说明靶机在所授权范围内没有响应的 TCP 服务，不能据此推断系统安全。

该验收只验证浏览器核心旅程和服务端保存的扫描结果；SSH 系统包、Trivy、Nuclei 规则命中仍需结合任务详情和 Worker 日志按测试方案分别核对。
