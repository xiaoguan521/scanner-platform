# 自定义漏洞规则

本平台的漏洞库由三部分组成，共同构成"完整漏洞库"：

1. **Trivy 版本库**：系统包/依赖的 CVE 版本匹配（离线库，GitHub Actions 打包签名）。
2. **公开 Nuclei 检测模板**：从固定版本的 nuclei-templates 过滤出的只读检测模板（GitHub Actions 管线）。
3. **自定义规则**：公司内部特有的检测特征，由管理员在平台内维护（本文件）。

## 范围边界（重要）

**本平台只做"安全扫描 / 检测"，不做攻击、利用、爆破或红方测试。** 攻击 / 红方
能力应由**另一个独立程序**承担，不在本平台实现，也不能通过自定义规则绕过。

因此自定义规则只能表达一种形式：**对目标某个同源路径发一个只读 GET，然后在响应
（正文 / 响应头 / 状态码）上做本地匹配。** 它在结构上就不接受 POST、请求体、
payload、fuzzing、多步请求、认证会话或其他 Nuclei 语法（Worker 侧 `ValidateTemplate`
+ 结构体严格解码双重把关）。

### 能表达 ✅
- 未授权暴露：内部管理页 / `/actuator/*` / `/.git/` / swagger 等不登录即可访问
- 版本 / 配置 / 调试信息泄露：响应中出现内部版本号、调试标记、敏感响应头
- 公司自研中间件的特征指纹

### 不能表达 ❌（属另一个独立程序的范畴）
- 越权 / IDOR（读取他人数据）、提权、下单改价、业务流程绕过
- 任何需要认证、带参数构造、发送 payload 或多步交互才能验证的逻辑漏洞

这些需要带认证的主动交互，属于红方 / 渗透工具，不在本平台实现。真正的逻辑漏洞
应由人工渗透完成，不要试图用自定义规则"编码"它们。

## 怎么添加

权限：管理员 / 安全工程师；写操作需带 CSRF 头。

### 方式一：平台 UI
`系统 → 规则库 → 自定义漏洞规则 → 新增规则`。填写 ID、名称、严重度、
**请求路径**（新增，以 `/` 开头，留空=根 `/`）、匹配方式（响应文本 / 正则 / 状态码）。

### 方式二：API
`POST /api/v1/custom-rules`

```json
{
  "id": "internal-actuator-exposed",
  "name": "内网 Spring Actuator 未授权暴露",
  "severity": "high",
  "path": "/actuator/env",
  "matchType": "word",
  "part": "body",
  "values": ["\"activeProfiles\""],
  "enabled": true
}
```

状态码型示例（检测某内部路径是否可直接访问）：

```json
{
  "id": "internal-admin-open",
  "name": "内部后台未授权可达",
  "severity": "high",
  "path": "/admin/dashboard",
  "matchType": "status",
  "statusCodes": [200],
  "enabled": true
}
```

## 字段约束

| 字段 | 说明 |
|---|---|
| `id` | `^[a-z0-9][a-z0-9_-]{0,99}$` |
| `severity` | info / low / medium / high / critical |
| `path` | 同源只读 GET 路径；以 `/` 开头；禁止二次 `{{}}`、反斜杠、空白；≤256 字符；留空=`/` |
| `matchType` | word / regex / status |
| `part` | body / header（status 型不填） |
| `values` | word/regex：1–8 条，每条 ≤256 字符 |
| `statusCodes` | status：1–10 个，100–599 |

## 存储与执行

自定义规则存于 Server 的 `custom_rules` 表，**不进签名 bundle**；创建扫描任务时
按任务注入，Worker 执行前再过一遍 `ValidateTemplate` + 作者/标签校验。删除规则不
影响已创建任务（保留创建时快照）。
