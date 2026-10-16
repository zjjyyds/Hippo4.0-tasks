# tests分析：binwalk_bmp_derived_stream

## 1.Instruction和Environment已经提供的信息

### 1.1 Instruction明确要求的功能与结果
1. **载体准入范围**：仅处理 24-bit、`BI_RGB`（无压缩，`compression == 0`）、40 字节 `BITMAPINFOHEADER`（`bi_size == 40`）、正高度（自下而上，`bi_height > 0`）的 Windows BMP 图像。载体可位于固件或二进制输入的任意物理偏移处。
2. **负面排除与边界限制**：明确声明无需支持 16/32-bit、负高度（自上而下）、V4/V5 扩展头、调色板、RLE 等其它 BMP 变体；这些不支持的格式即使内部包含符合 DBSF 魔数的内容，也绝不得产生任何派生流结果。
3. **顶层派生流单遍扫描**：派生扫描仅在输入顶层执行。从载荷中恢复出的数据即使内部包含嵌套的有效 DBSF 帧，也绝不得再次递归产生子级派生流输出。
4. **位级采样与跨载体拼接规则**：按照图像逻辑显示顺序（自顶向下、自左向右），对每个像素依次提取 B、G、R 三通道的最低有效位（LSB）。同一输入中若存在多个有效 BMP 载体，需按载体在输入中的物理出现顺序连续拼接比特流，严禁在载体切换时人为重置字节相位。
5. **DBSF v2 协议帧恢复**：从采样比特流中搜索 64 位同步标记（`0xB6, 0x5A, 0xE3, 0x81, 0x0C, 0xF4, 0x29, 0xD8`），支持非字节对齐（bit-slip）帧同步。
6. **TLV 扩展与 XOR 解扰**：支持解析扩展头 TLV 字段。遇到类型 1（`0x01`）且长度为 4 的 XOR 密钥时，对分片载荷进行循环滚动异或解扰；遇到未知非关键 TLV 标签（最高位为 0，即 Tag $\le 0x7F$）时必须正常跳过，不得报错或丢弃有效帧；遇到关键或保留非法标签时必须拒绝该候选帧。
7. **完整性校验**：必须验证分片 CRC32 与完整重组载荷的 CRC32。任何 CRC 校验失败的分片均不得采纳。
8. **乱序分片重组与会话冲突**：同一 `stream_id` 的多个分片允许以乱序到达，需按 `fragment_index` 重组为连续载荷；对于分片缺失、间隙、同一分片重复实例数超出声明（非正常重传）、或同一 `stream_id` 存在相互冲突的元数据时，必须整体拒绝，不得输出任意拼凑的派生流。
9. **签名引擎复用与过滤继承**：恢复出的完整载荷必须交由 Binwalk 现有签名分析引擎进行扫描；子签名偏移相对于载荷起始地址（0 虚拟基准）；且必须完全继承全局的 include/exclude 签名过滤参数。
10. **公开接口契约**：通过 `binwalker.enable_derived_streams(true)` 显式开启能力；默认关闭。关闭时原有扫描行为与输出 JSON 完全不变（不得出现 `derived` 键）。开启后在 `AnalysisResults.derived` 数组中输出包含 `kind: "bmp-fragmented-stream"`、`stream_id`、升序去重的 `carrier_offsets`、`total_payload_size`、整型数组形式的完整 `payload` 及 `file_map`。

### 1.2 Environment提供的技术条件与预置约束
1. **代码基线与依赖限制**：固定上游 Git Commit `26713972e3f9f52dc37d4a421c4554b0bd9e82ef`，严禁修改 `Cargo.toml` 或 `Cargo.lock`，严禁引入第三方外部 crate 运行时依赖，严禁在解题中调用外部系统级命令行解包子进程。
2. **预置工程骨架**：环境在 `src/binwalk.rs` 中预置了 `enable_derived_streams` 开关方法与 `scan_derived` 空实现骨架，在 `src/derived/mod.rs` 中定义了符合契约的 `DerivedResult` 数据结构，在 `src/derived/bmp.rs` 中预置了基础 24 位 BMP 载体识别与采样入口，消除了无关的 Cargo 胶水体力工作。
3. **构建与离线约束**：基于 Rust 官方工具链离线构建，`cargo check --offline --locked` 必须编译通过。

---

## 2.模型的理论通过路径

模型从现有仓库代码、Instruction 规范及公开样本出发，理论通过路径包含以下关键阶段与判断：

1. **入口接入与开关控制**：
   定位 `src/binwalk.rs` 的 `Binwalk::analyze_buf` / `scan` 流水线，识别 `self.derived_streams` 标志位。确保默认关闭时 `AnalysisResults.derived` 完全省略序列化，开启时调用派生分析逻辑。
2. **严格的 BMP 载体准入门控**：
   检查 `b"BM"` 魔数、`bi_size == 40`、`bi_bit_count == 24`、`bi_compression == 0` 以及 `bi_height > 0`。对负高度（top-down）、16/32 位深、V4/V5 扩展头、非零压缩（RLE/Bitfields）果断返回 `None` 丢弃，防止非目标图像参与比特流拼接。
3. **行步长对齐与自下而上反转采样**：
   按 Windows BMP 规范计算 4 字节对齐行步长 `stride = ((width * 3 + 31) / 32) * 4`；按 `(0..height).rev()` 逆序遍历物理扫描行，转换为自顶向下的逻辑图像显示行；逐像素提取 B、G、R 的最低有效位，并保持跨多载体的连续比特序列。
4. **非字节对齐位级帧同步与魔数搜索**：
   使用 64 位移位寄存器或逐位滑动窗口在比特流中寻找 `0xB65AE3810CF429D8` 同步字，正确处理跨越字节边界的非对齐偏移（bit-slip）。
5. **固定头反序列化与长度防护**：
   从同步点提取 `stream_id`、`total_len`、`header_len`、`fragment_count`、`fragment_index`、`payload_offset`、`fragment_len` 与 CRC。执行防溢出与边界检查（`payload_offset + fragment_len <= total_len`，`header_len >= 44`）。
6. **通用 TLV 扩展状态机与 XOR 解密**：
   遍历 `header_len - 44` 的扩展区域。识别 Type 1 的 4 字节 XOR Key；对未知标签检查最高位，若属于非关键标签（$\le 0x7F$）则按其长度安全跳过；对保留或非法标签拒绝该候选帧。使用 XOR 密钥对分片载荷实施滚动异或还原。
7. **会话聚合、冲突消解与分片重组**：
   建立以 `(stream_id, fragment_count, total_len, total_crc)` 为维度的独立会话管理。按 `fragment_index` 组装载荷，校验分片 CRC 与全量载荷 CRC；当同一分片出现多余物理实例，或同一 `stream_id` 存在不可调和的冲突元数据时，整会话予以废弃。
8. **签名扫描复用与虚拟偏移映射**：
   将还原出的 payload 直接传入 Binwalk 既有 `self.scan(&payload)` 引擎，继承 include/exclude 过滤器，子文件偏移自然落在以 0 为基准的虚拟空间，输出顶层派生分析结果。

---

## 3.Test检查点的依据

私有测试套件共包含 29 组随机化二进制业务用例、14 个自包含上游内置提取器原生回归目标，以及 8 个外部解包工具格式的可信签名扫描对照。每个检查点均具有直接的公开规范依据：

### 3.1 基础恢复与位级同步用例
- **Case 01（单分片 24-bit 基本恢复）**：检验单载体、单分片在标准 24-bit BMP 下的端到端恢复。依据：Instruction 需求 1、4、5、10。
- **Case 07（非字节对齐位级同步 bit-slip）**：DBSF 帧同步标记起点不在字节边界（偏移数 bit）。依据：Instruction 需求 4、5（明确要求支持非字节对齐同步）。
- **Case 37、40、53（跨载体比特相位连续性）**：帧跨越两个 BMP 载体分布，第一载体末尾 bit 无法凑满 8 位。依据：Instruction 需求 4（明确要求跨载体连续比特流不得重置字节相位）。
- **Case 41（载荷内部幽灵魔数抑制）**：有效载荷数据中偶然包含同步标记魔数字节。依据：必然成立的技术事实（必须根据帧长与校验合法性区分真伪同步标记，防止局部假匹配破坏完整帧）。

### 3.2 TLV 扩展与异或解扰用例
- **Case 08（TLV 滚动异或解密）**：携带 Type 1 密钥，对载荷进行 XOR 解码。依据：Instruction 需求 6。
- **Case 09（关键/保留标签拒绝）**：扩展区包含非法关键标签（最高位为 1）。依据：Instruction 需求 6。
- **Case 44（未知非关键 TLV 正常接受）**：扩展区包含合法的未知 Type 且后续跟随有效 XOR Key。依据：Instruction 需求 6（自描述非关键 TLV 必须被跳过，不得误杀有效帧）。
- **Case 56（无 Key 的非关键 TLV 扩展）**：扩展区仅包含未知非关键 TLV，无 XOR 密钥。依据：Instruction 需求 6。
- **Case 57（0 长度非关键 TLV 与极限边界）**：非关键 TLV 长度声明为 0，组合 16 字节合法密钥。依据：Instruction 需求 6。
- **Case 58（坏帧后继续同步）**：前置非法 17 字节密钥候选帧，后置合法帧。依据：Instruction 需求 7、8（坏帧拒绝后不得中止扫描，后续合法帧必须被正确恢复）。

### 3.3 分片重组、CRC 校验与会话冲突用例
- **Case 10、11（多分片按序与乱序到达重组）**：多载体中分片按序或颠倒乱序到达。依据：Instruction 需求 8（明确要求支持乱序分片重组）。
- **Case 13（损坏的分片 CRC 拒绝）**：分片数据损坏导致 CRC 不匹配。依据：Instruction 需求 7（明确要求验证分片与载荷 CRC）。
- **Case 26（前置诱饵伪魔数过滤）**：载荷前存在伪造的 DBSF 魔数碎片。依据：Instruction 需求 7、8。
- **Case 27（过时修订版本歧义消除）**：同一输入中包含废弃版本帧与最新修订帧。依据：Instruction 需求 8。
- **Case 42（完全相同分片重传拒绝）**：物理实例数大于声明分片数（非正常重传）。依据：Instruction 需求 8（异常分片实例破坏会话完整性）。
- **Case 48（尾部分片截断安全拒绝）**：载体容量在帧头中部中断。依据：Instruction 需求 1、7（不完整数据不得崩溃或产生假结果）。
- **Case 59（同 ID 同 CRC 的双会话共存）**：相同 StreamId 与 CRC 但分片数不同的两个完整会话共存。依据：Instruction 需求 8（会话状态机需以完整元数据聚合，不得混淆独立会话）。

### 3.4 契约负面用例（针对审核意见专项补充）
- **Case 60（负高度 top-down BMP 拒绝）**：输入为合法的 24-bit 负高度 BMP，内嵌有效 DBSF 帧。依据：Instruction 需求 1、2（明确限定仅处理正高度自下而上 BMP，不支持负高度，且不支持的变体绝不得产生派生流）。
- **Case 61（16-bit BMP 拒绝）**：输入为 16-bit BMP 并带有内嵌帧。依据：Instruction 需求 1、2（明确无需支持 16-bit，不得产生派生输出）。
- **Case 62（32-bit BMP 拒绝）**：输入为 32-bit BMP（含 Alpha 随机位）并带有内嵌帧。依据：Instruction 需求 1、2（明确无需支持 32-bit，不得产生派生输出）。
- **Case 63（BITMAPV5HEADER 124 字节 DIB 头拒绝）**：输入为 V5 头 BMP 并带有内嵌帧。依据：Instruction 需求 1、2（明确限定 40 字节 INFOHEADER，其余头大小一律不准入）。
- **Case 64（恢复载荷内部的嵌套幽灵帧拒绝）**：在合法恢复的顶层载荷内部植入另一段有效 DBSF 帧。依据：Instruction 需求 3（明确声明派生流扫描仅限顶层，恢复载荷内部不得递归产生二级派生输出）。

### 3.5 接口开关与原有行为兼容性用例
- **Case 23、49（开关关闭时 derived 字段严格缺省）**：在禁用派生扫描时执行扫描。依据：Instruction 需求 10（明确要求默认关闭，关闭时原有 JSON 不得出现 `derived` 键）。
- **Case 24_include / Case 24_exclude（签名过滤器继承）**：恢复出的载荷同时包含 ZIP 与 PNG，分别以 `--include zip` 和 `--exclude zip` 执行。依据：Instruction 需求 9（明确要求复用既有签名引擎并继承过滤行为）。
- **14 个自包含上游集成测试目标**（androidsparse、arcadyan、bmp、bzip2、csman、gzip、jpeg、matter_ota、mbr、pdf、png、qcow、riff、romfs）：在修改后的代码上完整运行上游回归套件，断言真实提取结果无一报错。依据：Instruction 需求 10、Environment 约束 1。
- **8 类外部解包工具依赖格式的签名扫描对照**（arj、cramfs、7z、squashfs、squashfs_v2、yaffs2、zip、zip_truncated）：使用独立可信原版 Binwalk 作为黄金对照，逐字段比对纯签名扫描结构（排查 UUID 差异）。依据：Instruction 需求 10（保持原有签名扫描行为不退化）。
