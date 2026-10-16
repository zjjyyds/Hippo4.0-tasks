# Task 3 V2 — SQLite WAL cross-acquisition evidence lineage

## 真实工程基础
- 上游：`SecurityRonin/browser-forensic`（Apache-2.0，Rust）；固定 SHA `10e2f70bd53d50144edcff849749efd0095c9a03`。
- 类别：攻防安全 / Forensics。
- 在上游 `browser-forensic-core` 追加小而封闭的 `wal_lineage` API，**不覆盖或修改第三题 V1**。

## 设计动机（仅审核员/出题人）
V1 的主要难点可收敛为 WAL 帧解析和提交物理镜像重建；强模型理解官方格式后存在快速求解风险。V2 将输入扩展为同一案件在不同观察点采集的 3～4 份主文件/WAL 证据，对每份证据恢复可证实的物理提交状态，再建立**仅受实际物证支持**的两两关系。

以下是互相独立的专业事实而非可按固定顺序套用的解题步骤：一份有效前缀并不保证尾部有效；内容一致并不证明采集属于同一执行过程；Checkpoint 兼容性只表示某次历史提交镜像与后续主文件物理一致；同一采集中间某次提交也可能是另一份证据的基底。不能暗示一定连续，也不能把旧帧当作新代提交。实现路径不限。

## 测试设计
- 32 个场景；4 种 SQLite 页大小；共计 3～4 份证据/场景。manifest 故意不按观察顺序排列，证据标识和目录名随机变化。
- 实际 `sqlite3` 生成事务及 Checkpoint；另有重签名 WAL、尾部损坏、提交前缀截断、旧世代错配、克隆副本、同终态不同 WAL 和历史中间提交匹配。
- 私有验证实际生成和核验每份数据库文件与 -wal，检测文件是否被修改，比较所有提交物理镜像、所有按次序的采集对及兼容证据帧列表。
- 与此前测试不同，32 个场景不是单纯复制 16 例再换顺序，既有随机化数据，也有多份证据的结构变化。

## 运行/验证状态
- Python 参考 Oracle + 真实 SQLite 原生恢复交叉检查已完成：3 种随机种子 × 32 场景；348 个有效采集视图，804 个已提交物理镜像前缀全部一致。
- 使用与 Rust starter 同形态的空 JSON 结构运行**实际 Python `verify.py`**：`0/32`、进程退出码 1，说明等价 NOP 失败。**这不是正式 Harbor Rust NOP 记录。**
- **真实 Rust CI 验证已通过**：GitHub Actions Run [38830986366](https://github.com/zjjyyds/Hippo4.0-tasks/actions/runs/38830986366) 在 Rust 1.88.0 下完成源码编译，Rust NOP 0/32，标准解法 Oracle 32/32，上游核心测试 75/75。运行证据在 `oracle_verification.log`。
- 正式 Harbor Docker 环境尚未验证；不能将 GitHub Actions 通过等同于 Harbor Oracle 1.0。
- 未运行五次 SOTA Agent，因此尚不能宣称 Mean ≤ 0.4、平均交互 ≥80 或一小时内全部完成。这些必须靠真实 Agent 试跑确认。

## 难度与耗时
- 任务仍是 Rust 库中一个独立接口，不扩展为浏览器全盘取证平台。
- 数据主要是 KB 级短 WAL，验证时重用一次 Rust 构建产物，每个场景最多调用候选程序一次。
- 目标是在一次合理 Agent 时间预算内发生协议与证据层的复杂推断，而非大数据 IO 或环境障碍。Agent 3600 秒，Verifier 600 秒，Docker Build 600 秒。

## 可见信息界限
仅 `instruction.md`、公开 API 空实现及固定上游工程作为模型必须获知的条件；不将 `solution/`、`tests/`、本 README 的出题思路暴露给 Agent。测试/Oracle 属于独立验证环境。
