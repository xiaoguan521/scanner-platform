# PoC 2：租约与规则版本回收

范围：规则版本固定、Server 租约、Worker 失联自终止、Updater 两阶段 GC 和 `CURRENT` 原子切换。

验收：运行任务引用的版本不会回收；续租持续失败超过租约时长后扫描停止；硬截止时间在 Server 不可达时仍生效；Linux、Windows 下切换 `CURRENT` 的行为经过验证。

当前为验收规格，尚无实现或压测结果。
