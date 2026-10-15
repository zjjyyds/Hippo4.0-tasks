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

## 验证状态
- Python 独立生成器目前可生成全部 24 例与期望值。
- 参考 Rust 实现已提供，**当前执行容器没有 cargo/rustc/Docker，因此尚未进行真实 Rust 编译和 Harbor Oracle/NOP**。
- 在宣布任务可正式送审前，必须进行 Docker 镜像构建、Oracle/NOP 对照，以及至少一次模型试跑诊断。不要把纯 Python 期望值测试等同于 Oracle 完成。
