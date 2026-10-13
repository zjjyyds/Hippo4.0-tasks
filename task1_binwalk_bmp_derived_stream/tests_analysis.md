# 精简版 DBSF 任务：测试分析与归因（已修订回归边界）

## 1. 公开要求
仅实现 24-bit BI_RGB、40 字节 INFOHEADER、正高度 bottom-up 位图中的 DBSF v2。支持跨载体非字节对齐位拼接、TLV/XOR、乱序分片与异常会话判定。仅顶层派生扫描；恢复完整 payload，并通过既有 Binwalk 签名引擎继承 include/exclude。默认关闭时须与原始扫描结果兼容。题面明确不要求 16/32-bit 与派生递归。

兼容性契约限定：原始库/二进制测试和不依赖额外系统级解包工具的上游提取器回归必须通过。对 ARJ、CramFS、7z、SquashFS、YAFFS、ZIP 相关旧输入，要求派生功能关闭时签名扫描行为与固定原版相同；不声称在缺少第三方工具时验证了实际解包过程。

## 2. 理论通过路径
定位 Binwalk 扫描入口及 AnalysisResults，逆向公开样本，恢复采样位序、魔数帧同步、TLV/XOR、CRC、分片乱序与会话独立性；将真实载荷输入原签名引擎，同时保证关闭开关时签名行为与原始版本一致。不能用固定摘要、样本名称或枚举测试输入替代通用恢复逻辑。

## 3. Test 依据和覆盖
- Step 0：校验 Cargo 文件未变，源代码及隔离边界限制派生流外部调用，对应公开依赖约束。
- Step 1：执行库/二进制及 14 个自包含上游集成目标：androidsparse、arcadyan、bmp、bzip2、csman、gzip、jpeg、matter_ota、mbr、pdf、png、qcow、riff、romfs。真实提取结果均受上游断言检查。
- Step 2：从修改后的 Binwalk 编译公开 API harness，确保可以完成真实接口调用。
- Step 3a：**24 条随机化业务用例**，包括基本恢复（01）、位级同步（07）、TLV/XOR（08、09、44、56、57）、乱序/CRC/冲突（10、11、13、27、42、59）、默认关闭（23、49）、过滤（24_include、24_exclude）、坏帧处理（26、48、58）、跨载体 bit 相位（37、40、53）、帧内部候选抑制（41）。verifier 实际对完整 payload 计算 SHA-256，并以独立可信原版 Binwalk 的全量签名映射比较结果。
- Step 3b：从 verifier 镜像固定上游 commit 拷贝 8 个只读测试输入（arj.bin、cramfs.bin、7z.bin、squashfs.bin、squashfs_v2.bin、yaffs2.bin、zip.bin、zip_truncated.bin），对修改版及原版使用完全相同的输入进行**纯签名扫描对照**，比较所有结构化签名字段（随机 UUID 除外），并确认无 derived 字段。这是相对于旧版只跑 14 个目标的新增兼容性覆盖；不伪称已执行需要 7zz、sasquatch、unyaffs 等第三方工具的原生提取/解包回归。

## 4. 验证与实测结论
已在独立 Docker 环境与 Harbor 评测流水线中完成真实端到端验证：
1. **Oracle 验证**：执行 `solve.sh` 替换 starter 骨架后，24 组私有用例 100% 通过（24 passed, 0 failed），14 个原生集成目标全过，8 个历史签名扫描对照全过，判定为 **Reward 1.0 (PASS)**，全流程耗时 3 分 35 秒（远低于 600 秒上限）。
2. **NOP 基线**：初始代码与骨架在评测机上稳定判定为 **Reward 0.0 (FAIL)**，不存在提前偷分或测试泄露。
3. **真实 5 轮模型试跑**：GPT-5.6-sol 独立运行 5 轮，成功 1 轮、失败 4 轮（其中 2 轮在做题中用尽 1 小时时限产生 AgentTimeoutError，0 次基础设施安装故障），平均单次交互 91.2 轮，实跑平均成功率（Mean）为 0.200（1/5），符合难度控制指标。

## 5. 一小时能力评测预算
`task.toml` 的 Agent 运行上限为 3600 秒（1 小时），Verifier 仍为 600 秒，Environment 构建仍为 600 秒。此限制用于完整进入任务后的 Agent 解题执行，不把环境安装超时计入能力失败。

## 6. 公开工程骨架与快检机制
在 Agent 环境 Docker 构建、固定上游 commit 后，新增必要的接口与基础工程胶水：`/task_docs/starter.py` 为 `src/binwalk.rs` 添加 opt-in API 及未实现的 `scan_derived`，新增 `src/derived/mod.rs` 结果数据类型和 `src/derived/bmp.rs` 的 24 位 BI_RGB 基础载体发现/像素 LSB 采样骨架。这些内容不包含 DBSF v2 的帧同步、TLV/XOR、CRC、分片或会话冲突推理。已有 Binwalk 函数和测试保持完整。核心考察点依然是跨载体比特相位、TLV 边界与冲突处理。

`/task_docs/public_check.py` 是 Agent 可见的、仅从 10 份公开样本 MANIFEST 提取预期 stream ID/长度/载体偏移/SHA-256 的**单次快速自检**。公开样本通过且无具体错误时题面明确要求停止，不再进行重复全量回归。错误时可继续针对性修复。Verifier 独立执行 24 私有用例、14 原生上游回归及 8 项可信签名对照，评分条件严格隔离。

Oracle `solve.sh` 在检测到明确标记的 starter stub 时恢复其原始上游文件，并以既有 `solution.patch` 实现完整逻辑，已通过实机打分。

## 7. 三条轻量协议边界设计（Case 57/58/59）
- **Case 57**：未知非关键 TLV 长度为 0，合法 16 字节 XOR key 与错位帧同步组合。
- **Case 58**：17 字节非法密钥候选在前，后续有效帧不得被遮蔽，检验错误容错恢复能力。
- **Case 59**：两个独立完整会话具有相同 StreamId、TotalCRC、TotalLength，但 FragmentCount 不同（1 和 2），应分别输出各自 carrier_offsets，检验会话字典去重的正确性。
每条用例直击协议状态机边界，全量 24 组用例已全部闭环验证。
