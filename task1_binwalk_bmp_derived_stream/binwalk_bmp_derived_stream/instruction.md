# 固件位图资源中的 DBSF 派生数据流恢复（精简版）

设备固件的 BMP 像素中可能隐藏二级诊断数据流（DBSF v2），原厂工具链和协议文档已失传。请在固定版本的 Binwalk（Rust）上新增可选的恢复与分析能力。

阅读现场笔记：`/task_docs/derived-bitmap-stream.md`；公开样本及其声明：`/task_docs/samples/MANIFEST.md`。线格式需从样本逆向，验收使用同协议的新固件数据。

## 支持范围

1. 仅处理 **24-bit、BI_RGB（不压缩）、40 字节 BITMAPINFOHEADER** 的 BMP 载体；它们可能位于固件任意偏移。需正确处理行步长、padding、行方向和同一输入中的多个载体。**无需支持 16/32-bit、V4/V5 头、调色板、RLE 等其它 BMP 格式。**
2. 从采样的像素比特恢复 DBSF v2：支持非字节对齐同步、跨载体连续比特流（不得错误重置字节相位）、TLV 扩展与可选 XOR、乱序分片重组，以及损坏帧和冲突会话的拒绝。协议正确性以公开样本定义的正反行为为依据。
3. 将真实恢复的 payload 送入 Binwalk 现有签名引擎，继承 include/exclude 过滤，子签名偏移相对于 payload。**不要求对恢复的 payload 继续递归派生流扫描。**

## 接口与兼容性

- `binwalker.enable_derived_streams(true)` 开启该能力；默认关闭，关闭时原有行为和 JSON 均保持不变（不得出现 `derived` 键）。
- 在 `AnalysisResults.derived` 输出 `kind`、`stream_id`、升序去重的 `carrier_offsets`、`total_payload_size`、完整的 `payload: Vec<u8>` 和 `file_map`。kind 为 `bmp-fragmented-stream`，不要求嵌套结果。
- `payload` 序列化为**完整字节整数数组**，长度等于 `total_payload_size`。验收会计算 SHA-256，并对照可信 Binwalk 扫描结果核对子签名和过滤；只返回摘要或文本不算恢复。
- 不得修改 `Cargo.toml` / `Cargo.lock`，不得新增运行时依赖或调用外部子进程。**所有既有库、二进制及内置提取器回归测试必须保持通过。**
