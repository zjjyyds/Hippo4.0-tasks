# Task 3 V2 — tests分析

## 1.Instruction和Environment已经提供的信息

**Instruction：**
- 目标：完成 Rust 公共接口 `browser_forensic_core::wal_lineage::inspect_wal_lineage(root: &Path) -> std::io::Result<WalLineageReport>`。Environment 已提供公开类型和可编译的空实现，不限定求解方法。
- 输入：`root/manifest.json` 中每项 `captures` 包含 `id`、`order`、相对路径 `db`。清单可乱序，SQLite 主文件可带同名 `-wal` 侧车；`order` 不自动证明真实事件连续。
- 观察结果：`captures` 按 `order` 返回 `id`、`base_sha256`、`commits`、`terminal_sha256`；每个有效提交包含从 1 开始的 `end_frame`、`database_pages` 及完整物理数据库页镜像的小写 SHA-256；无有效提交时终态为主文件摘要。
- 证据关系：`links` 涵盖全部有序观察对，按先前与后续观察排序，字段为 `from`、`to`、`relation`、`anchors`。关系依最具体证据选择 `identical_evidence`、`shared_wal_prefix`、`checkpoint_compatible`、`equal_result_only` 或 `unproven`；第三类的 `anchors` 列出全部匹配的先前提交帧，其他关系为空。结果相同不等于证明事件同源。
- 边界：损坏、撕裂、未提交和不可证实的 WAL 不产生提交；有效提交前缀仍应保留。缺少 WAL 允许；主文件缺失或无效则报错。原物证不得修改，原核心库行为兼容。

**Environment：**
- 上游为 `SecurityRonin/browser-forensic`，固定提交 `10e2f70bd53d50144edcff849749efd0095c9a03`；`environment/starter.py` 提供上述接口及空实现；依赖在构建阶段准备，执行时离线。
- `task.toml` 声明 artifacts `/workspace/browser-forensic`、独立 Verifier，以及 Agent / Verifier / Build 的 3600 / 600 / 600 秒限制。
- Instruction 和 Environment 均未限定内部算法、辅助函数名、代码布局、日志文本或调试过程，私有实现细节不得作为额外的强制 Test 条件。

## 2.模型的理论通过路径

1. 从公开 API、真实上游工程与 manifest 契约明确多个观察点的读取范围及结果结构。
2. 依据 SQLite 公开持久化格式，确定各观察点可证明的 WAL 提交状态，恢复对应物理视图及摘要；正确处理无侧车、受损尾部和无效主文件。
3. 对每个按 `order` 形成的观察对判断最具体的物证关系，区分直接字节证据、已提交历史匹配与仅终态相同，并完整返回适用的历史匹配帧。
4. 验证 JSON 输出、顺序、错误处理、只读行为和既有库回归。可以采用任意与契约一致的实现方式，不要求执行特定调试流程。

上述路径由题面明确的结果定义、公开输入格式和可访问的上游源码支持；难点在于可证实的物理状态与跨观察关系的判断，而非隐藏字段或私有算法猜测。

## 3.Test检查点的依据

| 实际检查点 | 对应 Instruction / Environment 依据 |
|---|---|
| 随机命名与无序 manifest；按 `order` 返回全部观察并保留正确 ID | Instruction 明确 manifest 三字段、条目可乱序及输出顺序 |
| 每个 `commit` 的帧序号、数据库页数和物理镜像摘要，以及 `base_sha256`、`terminal_sha256` | Instruction 对字段、物理镜像含义、摘要格式及无提交时的终态均有显性要求 |
| 有效 SQLite 不同页大小和多次真实事务产生的提交历史 | 输入明确为 SQLite 主文件与 WAL；这是正常受支持格式和事务行为，不限定内部解析方法 |
| 损坏尾部、世代不匹配、无效或未提交的 WAL 不增加伪提交；保留此前有效前缀 | Instruction 对不可证实数据和已验证前缀的直接要求 |
| 全部有序观察对的 `links`、顺序、`from` 与 `to` | Instruction 明确要求每一对有序观察，不仅相邻观察 |
| 五类关系的结论与最具体关系优先级 | Instruction 明列五种证据关系及各自成立条件 |
| `checkpoint_compatible` 列出所有匹配历史帧，包括中间提交；其他关系 `anchors=[]` | Instruction 明确全部匹配帧与非此关系时的空数组要求 |
| 相同终态但没有更强连续性证据时不错误推断同源；证据不足采用 `unproven` | Instruction 明确将证据兼容性与现实事件身份区分 |
| 无 WAL 可正常返回，无效 SQLite 主文件需报错 | Instruction 的成功与异常输入边界；只验证错误发生，不指定错误文案 |
| 运行前后主文件与 WAL 的哈希保持一致 | Instruction 明确取证材料不得改变 |
| Rust 公共 API 编译及 `browser-forensic-core` 既有单测通过 | 公开的 Environment 接口和 Instruction 的原有行为兼容要求 |

**测试与判定边界：**
- `generate_cases.py` 每次生成 32 个随机化案件，来自 4 种 SQLite 页大小与 8 类证据结构，每案含 3～4 份观察。真实 `sqlite3` 事务及 checkpoint 生成物证，再加入受控变化；随机化数据、采集 ID、路径及 manifest 顺序。32 例不是 32 个独立协议知识点。
- `verify.py` 只比较完整输出、异常行为及原始物证哈希；`test.sh` 编译候选 Rust 接口、运行既有单测并在全体测试通过时给出成功奖励。没有要求固定算法、内部函数、源码文本、调试操作、日志格式或 SQL 行恢复。
- Python 参考生成预期物理镜像，与 Rust 参考实现独立；`self_test.py` 进一步用真实 SQLite 引擎交叉核对 3 × 32 案件的 348 份采集及 804 个已提交前缀。这验证物理结果，不等于 SQLite 引擎独立裁决了所有跨观察关系。
- GitHub Actions [Run 38830986366](https://github.com/zjjyyds/Hippo4.0-tasks/actions/runs/38830986366)：Rust starter/NOP 0/32，参考解法 32/32，原核心单测 75/75。它不是 Harbor Docker Oracle；正式 Harbor 闭环仍待执行。
- 尚无五轮 GPT-5.6 / Opus 试跑证据，不能宣称平均轮数或通过率达标；基础设施故障不得视为模型能力失败。

本分析仅阐明已有题面与环境允许的 Test 依据，不为 Agent 新增强制条件。