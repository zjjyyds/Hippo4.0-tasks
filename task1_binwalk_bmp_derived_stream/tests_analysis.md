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
