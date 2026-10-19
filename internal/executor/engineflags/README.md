# 固定版本与参数白名单

引擎版本固定在 `config/engines.lock.json`，下载 SHA-256 来自相应官方 GitHub release。`args.go` 是运行参数白名单；不接受用户自定义参数。`make engines` 安装、准备规则，`make verify-flags` 对实际程序版本和帮助输出逐项核对。

Nuclei 3.11.1 使用 `-fhr` 将重定向限制在同一主机；不能与 `-dr` 同时使用（引擎会拒绝启动）。禁止 `-lna`、`-code`，仅 HTTP 根路径 GET 的受限 JSON 模板，排除 code/headless 等协议、禁用 OAST、更新和非 URL 探测。限速与超时来自 Worker 配置，并发固定为 1。

Trivy 0.76.0 使用 filesystem 分析项目锁文件、`rootfs --pkg-types os` 分析系统包，或 `rootfs --pkg-types library` 分析明确选择的 JAR/Go 部署文件。Go 分析固定 `--file-patterns gobinary:.*`，不需要执行权限、不运行输入。Java 索引只由 Updater 的显式 `--download-java-db-only` 准备，扫描进程禁用更新。Docker tar 直接输入，OCI tar 由 Worker 按严格布局私有解包、校验 blob 哈希后交给 `image --input`，结束后清理；只接受单平台镜像，不解开容器层。ZAP 2.17.0 只导入已经记录的 HAR 响应并运行被动扫描，`-silent -notel`，不创建爬虫或主动扫描任务。

详见 `docs/engines.md` 与 `docs/verification-log.md`。本地参数与夹具验证不等同于真实服务器覆盖验证。
