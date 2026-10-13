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
- Step 3a：21 条随机化业务用例，包括基本恢复（01）、位级同步（07）、TLV/XOR（08、09、44、56）、乱序/CRC/冲突（10、11、13、27、42）、默认关闭（23、49）、过滤（24_include、24_exclude）、坏帧处理（26、48）、跨载体 bit 相位（37、40、53）、帧内部候选抑制（41）。verifier 实际对完整 payload 计算 SHA-256，并以独立可信原版 Binwalk 的全量签名映射比较结果。
- Step 3b：从 verifier 镜像固定上游 commit 拷贝 8 个只读测试输入（arj.bin、cramfs.bin、7z.bin、squashfs.bin、squashfs_v2.bin、yaffs2.bin、zip.bin、zip_truncated.bin），对修改版及原版使用完全相同的输入进行**纯签名扫描对照**，比较所有结构化签名字段（随机 UUID 除外），并确认无 derived 字段。这是相对于旧版只跑 14 个目标的新增兼容性覆盖；不伪称已执行需要 7zz、sasquatch、unyaffs 等第三方工具的原生提取/解包回归。

## 4. 当前限制
此修订明确缩小了公开兼容性要求的范围，并提供额外扫描验证；是否满足最终审核需由评审判断。没有在当前工具环境中运行 Docker/Harbor Oracle 或新版 5 次模型试跑，不能沿用旧版 reward、轨迹或 pass@5。提交前必须先验证 Oracle、verifier 600 秒限额、API/subagent 健康以及新版独立的 5 次试跑。

## 5. 一小时能力评测预算（2026-10-13）
`task.toml` 的 Agent 运行上限改为 3600 秒，Verifier 仍为 600 秒，Environment 构建仍为 600 秒。此限制仅用于完整进入任务后的 Agent 执行，不将 AgentSetupTimeoutError（0 步、360 秒）记为能力失败。平台可覆盖 task.toml，正式试跑须核对 job 最终解析配置。

已有一次 120 步、43 分 21 秒、19/21 的有效失败，以及一次 268 步、2 小时 42 分 18 秒、21/21 的有效通过，说明尚不能凭两条轨迹确认 1 小时下的真实 pass@5。新版仅调整时间预算，不删减业务验证或修改 Oracle。过往试跑不再用于新预算的 pass@5 结论。建议先单并发完成 Agent 安装预检，再五轮独立试跑并逐个记录是否 setup、API、agent timeout 或 verifier 业务失败。

## 6. 新版提供的公开工程骨架与快检（2026-10-13）
在 Agent 环境 Docker 构建、固定上游 commit 后，只**新增**必要的接口/基础实现：`/task_docs/starter.py` 为 `src/binwalk.rs` 添加 opt-in API 及未实现的 `scan_derived`，新增 `src/derived/mod.rs` 结果数据类型和 `src/derived/bmp.rs` 的 24 位 BI_RGB 基础载体发现/像素 LSB 采样。这些内容不包含 DBSF v2 的帧同步、TLV/XOR、CRC、分片或会话推理。已有 Binwalk 函数和测试没有删除。真正的困难仍然是跨载体比特相位、TLV 边界与冲突处理。

`/task_docs/public_check.py` 是 Agent 可见的、仅从 10 份公开样本 MANIFEST 提取预期 stream ID/长度/载体偏移/SHA-256 的**单次快速自检**。由公开 Cargo example 调用真实库扫描，不读取隐藏 Test，不影响 verifier 判定。公开样本通过且无具体错误时题面明确要求停止，不再进行重复全量回归。错误时可继续针对性修复。Verifier 独立执行 21 私有用例、14 原生上游回归及 8 项可信签名对照，**任何 Test/评分条件未变**。

Oracle `solve.sh` 仅在检测到明确标记的 starter stub 时恢复其原始上游文件，并以既有 `solution.patch` 实现完整逻辑；这一步不修改测试或评分，也不会依赖事先隐藏的代码。需在真实 Docker/Harbor 下验证新的环境构建、Oracle 21/21 及 10 分钟的 verifier 上限。新任务内容与旧 5 次轨迹已不相同，必须重新实测，不可把先前 0 步安装失败计入能力失败。


## 7. 三条轻量、非常规协议边界（2026-10-13）
私有 case57：未知非关键 TLV 值长度为 0，合法 16 字节 XOR key 与 3-bit 错位帧同步组合；case58：17 字节非法密钥候选在前，后续有效帧不得被遮蔽；case59：两个独立完整会话具有相同 StreamId、TotalCRC、TotalLength，唯 FragmentCount 不同（1 和 2），应分别输出各自 carrier_offsets。每条仅使用短 24-bit BMP，考的是组合语义而非格式范围。

私有业务验收现为 **24 条**，保留 14 个原生回归目标、8 个签名对照、1 小时 Agent 预算及公开 10 样本单次快检。现场笔记已补充这三个边界的行为依据。尚未完成新版 Docker Oracle 或五次独立试跑。
