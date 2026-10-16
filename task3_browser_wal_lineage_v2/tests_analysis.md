# 第三题 V2：tests分析与Test边界

## 1.Instruction和Environment已经提供的信息

- **任务目标与接口（Instruction）：** 在固定版本的 `SecurityRonin/browser-forensic` 中实现 `browser_forensic_core::wal_lineage::inspect_wal_lineage(root: &Path) -> std::io::Result<WalLineageReport>`。环境已提供公开数据类型和可编译的空实现；不限定内部算法或修改方式。
- **输入（Instruction）：** `root/manifest.json` 的 `captures` 条目包含 `id`、`order`、`db`；条目可以无序，`db` 为相对路径，对应 SQLite 主文件，可带同名 `-wal`。观察点的 `order` 只定义先后顺序，不自动证明取证材料来自同一次连续执行。
- **每份采集的结果（Instruction）：** `captures` 按 `order` 输出，包含 `id`、`base_sha256`、`commits`、`terminal_sha256`；每次有效 WAL 提交记录包含 `end_frame`、`database_pages` 和完整物理数据库页镜像的 SHA-256。没有有效提交时，终态摘要为主文件摘要。
- **跨采集关系（Instruction）：** `links` 覆盖每一对按观察顺序排列的采集，按前后采集排序；包含 `from`、`to`、`relation`、`anchors`。关系按照题面给出的证据强度次序选择：`identical_evidence`、`shared_wal_prefix`、`checkpoint_compatible`、`equal_result_only`、`unproven`。`checkpoint_compatible` 的 `anchors` 要列出所有能见证匹配的历史提交帧，其余关系为空列表。关系表示物证的兼容性，不是对现实事件同源性的断言。
- **边界与兼容性（Instruction）：** 不得把损坏、撕裂、未提交或无法核实的 WAL 数据报告成已提交状态；尾部受损时保留此前可证实的有效提交前缀。缺少 WAL 允许，主文件缺失或无效必须报错；不得修改证据文件；保留 `browser-forensic-core` 原有行为。
- **环境显性条件（Environment、task.toml）：** 基础工程 checkout 固定到 `10e2f70bd53d50144edcff849749efd0095c9a03`，语言 Rust，已预置 starter API 和上游依赖，运行时离线。Agent、Verifier、Environment Build 的限制分别为 3600、600、600 秒，Verifier 为 `separate` 模式。Agent 可见内容不包含私有标准解法或验证数据。

## 2.模型的理论通过路径

1. 从题面、starter 公开类型及固定版本的上游工程理解入口、证据文件组织和现有 SQLite 访问能力，确定新增接口与既有 crate 的兼容边界。
2. 根据 SQLite 主文件和 WAL 的公开持久化格式，自主判断哪些物理记录足以证明一次已提交视图；为每个观察点还原有效历史、完整物理镜像摘要以及终态。对于缺失、损坏或不完整材料，应区分可证明前缀与不可证明尾部。
3. 在全部观察点的结果基础上推断每一对有序采集之间可由物证支持的最具体关系。既要识别直接的字节证据，也要处理结果相同但关联证据不足的情况；需要检查历史中间提交是否也能提供合法 `anchors`。
4. 检查有 WAL、无 WAL、边界异常和原有功能回归，确认结果顺序、字段、错误处理和原文件不变性。模型可以自由选择实现、调查和调试方法；题面不要求执行指定测试命令，也不限制采用何种正确的数据结构。

**核心难点：** 单份证据的提交历史可信性、跨观察点的关联证据强度和“同一最终结果不等于同一历史来源”的区分。理论路径不代表标准答案的唯一实现路径。

## 3.Test检查点的依据

以下检查只验证可观察行为；不按源码结构、辅助函数、特定解析算法、调试顺序或日志文本评分。

| 核心检查点 | Test 中的验证方式 | 依据 |
|---|---|---|
| 输入解析及采集顺序 | 构造多份采集，随机化文件名、标识及 manifest 条目排列；核对输出 `captures` 顺序与 `id` | Instruction 明确 `manifest.json` 格式、相对路径和 `order` 语义 |
| 主文件与 WAL 提交历史 | 真实 SQLite 生成短事务和多次提交，核对提交帧编号、数据库页数及各次完整物理镜像摘要 | Instruction 的 `commits` 字段与有效提交镜像定义 |
| 终态与无 WAL 情况 | 校验 `base_sha256`、`terminal_sha256`；包括有效提交及无可用提交的材料 | Instruction 的三个摘要/历史字段及无有效提交时的终态定义 |
| 损坏数据及前缀保留 | 对残缺尾部、无效提交信息、WAL 世代不匹配等材料检查不会凭空增加已提交视图，且不丢弃更早的有效前缀 | Instruction 明确排除无效/未提交数据并保留可证实前缀；SQLite 文件格式是输入物证的客观语义 |
| 有序采集对的完整性 | 校验所有前后有序的采集对及 `links` 的排列，不只校验相邻两份 | Instruction 明确“one entry for each ordered pair”及排序要求 |
| 证据关系与优先级 | 使用相同物证、共享已验证 WAL 前缀、提交镜像与后续主文件匹配、仅终态相同以及证据不足的样本，核对最具体的可证明关系 | Instruction 明列五个关系的定义及优先次序 |
| `anchors` 的真实性与完整性 | 在 `checkpoint_compatible` 情形核对所有匹配的先前提交帧，包括可能的中间提交；其他关系要求空数组 | Instruction 对匹配提交帧和非该关系的 `anchors` 有显性约束 |
| 缺失/无效主文件 | 两个异常主文件场景要求接口返回错误；缺少 WAL 不作为错误 | Instruction 明确错误边界 |
| 只读取证材料 | 执行前后分别哈希每份主文件与存在的 WAL，确认原始字节未改动 | Instruction 明确证据文件必须保持不变 |
| 原有功能回归与可调用性 | 编译公开 Rust API、调用 harness，并运行上游 `browser-forensic-core` 单元测试 | Instruction 明确原有行为兼容；Environment 公开的 Rust crate 和 starter 接口 |
| 空实现区分度 | 使用 starter 空实现独立运行评分器，必须不能通过全部场景 | 初始状态必须暴露待实现需求，且 Test 不能让空操作通过的通用验收要求 |

**测试范围说明：** 32 个随机化案件来自 4 类页大小与 8 类证据构造，每案含 3～4 份采集；随机化数据、标识和部分采集布局。它们不是 32 个完全独立的底层协议原理，也不能把排序变化计为新的专业难点。当前任务仅要求提交历史及证据关系，不要求 SQL 行内容恢复、真实浏览行为归因或文件系统全盘取证，因此未将这些能力纳入强制检查。

## 4.运行与验证证据（补充）

- GitHub Actions Run [38830986366](https://github.com/zjjyyds/Hippo4.0-tasks/actions/runs/38830986366)：使用 Rust 1.88.0 编译真实 starter/harness；NOP **0/32**，参考实现 Oracle **32/32**，上游核心单测 **75/75**。运行摘要见 `oracle_verification.log`。
- 参考 Python 物理格式分析独立于 Rust 解法；真实 SQLite 引擎对 3 轮 × 32 案件中的 **348 份采集、804 个提交前缀**进行物理状态交叉核验，详见 `sqlite_independent_verification.log`。这些数量代表核验规模，不是独立题型数量。
- 验证器运行时动态生成证据并核对最终 JSON 与原始证据哈希；私有测试、参考实现和 reward 不提供给 Agent。Agent 仅获得固定上游工程、starter 公开 API 和 `instruction.md`。
- **尚未完成：** 正式 Harbor Docker Oracle/NOP 环境闭环、五轮 GPT-5.6/Opus 试跑、平均交互轮数和实际通过率。因此不能宣称 80 轮或低通过率已经达标；基础设施失败不计作模型能力失败。
- 本文档仅是审核说明，不会给 Instruction 或 Environment 增设隐性强制条件，也不替代原始行为测试。
