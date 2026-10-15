# 第三题：browser_forensic_wal_lineage

## 基础项目
- GitHub: https://github.com/SecurityRonin/browser-forensic
- Pin: `10e2f70bd53d50144edcff849749efd0095c9a03`
- Rust `browser-forensic-core`（现有 SQLite 证据只读访问基础设施）
- 提交领域：攻防安全 / Forensics

## 设计理念（仅供出题人与审核员阅读，不提供给 Agent）
核心难点是根据真实 SQLite 主文件及 WAL 的**有效提交边界**还原每一次可证明的持久化数据库物理视图。单纯扫描到更多帧、SQLite 当前视图能读、或文件字节中出现了历史内容，并不能自动证明它们属于已提交事务。任务不要求 Agent 修复整个 WAL 解析器，也不限定算法。

区别于上一道 D4 TCP 题：这里的失败不是某个单一排序缺陷，而是证据合法性与快照状态之间的约束错误。一个看似可信的结果，可能对未提交尾部、校验断链、旧 checkpoint 残留或校验端序产生过度肯定。小规模测试即可让错误出现，不必堆数据量。

## 测试设计
24 个结构不同且每次随机化载荷的 SQLite/WAL 案例，以 Python sqlite3 原生执行真实事务后保留真实证据快照，并由独立 Python 参考解析逻辑生成预期；覆盖合法多提交/重写页面、多种页大小、额外尾部、未提交帧、校验断链、无效盐、旧世代、两种合法校验端序和不合法头部。预期是每次提交的页数、提交帧和完整物理镜像 SHA-256，并非源码/算法模式匹配。

## 工作量与预期
- 主要改 `crates/browser-forensic-core/src/wal_lineage.rs`（已有公开 stub）；其余上游代码保留。
- Agent 3600 秒，Verifier 600 秒，Environment Build 600 秒。
- 每个测试用例 KB 级到少量十 KB；验收阶段只需一次 Rust harness 编译、短文件解析和现有核心库回归。
- 初步目标 Mean<=0.4、平均 >=80 轮；**未经 5 轮真实 Agent 试跑，不得认定这些指标已经实现**。

## 验证状态（2026-10-15 更新）
- 24 个随机化案例及期望值可由真实 SQLite 事务生成，独立 Python 参考与 SQLite 原生引擎对照运行 3 × 24 个场景，通过。
- `oracle_verification.log` 已作为单独证据提交：记录 24/24 私有案例和 75/75 Rust 原生单测通过。该日志属于其他运行环境的验证记录；当前会话环境未再次执行 Cargo/Docker。
- `nop_equivalent_verification.log` 记录了以**提供的 Rust starter 空实现 `Ok(Vec::new())` 等价输出**驱动实际 `tests/verify.py` 的脱机试验：6/24、退出码 1。该结果支持 NOP 的预期 reward=0，但不是 Harbor 中编译运行 Rust NOP 的实测记录。
- **仍未完成：正式 Harbor NOP、五次真实 SOTA Agent 试跑及 >=80 步的难度判定。** 不应将这几项标记为已通过。
- 上述更新仅涉及审核说明与独立验证日志，Agent 题面、测试、标准解法及 ZIP 均保持不变。
