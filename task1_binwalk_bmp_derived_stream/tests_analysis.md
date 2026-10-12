# binwalk_bmp_derived_stream：精简版测试分析

## 1. Instruction 和 Environment 已公开的信息
新任务只支持 24-bit BI_RGB / 40 字节 BITMAPINFOHEADER 的 BMP 载体；不要求 16/32 位、压缩及 V4/V5 BMP，也不要求多层递归。必须支持位级帧同步、跨载体不对齐拼接、TLV/XOR、乱序分片与异常会话拒绝；恢复的完整 payload 必须交给原 Binwalk 签名扫描并继承 include/exclude。默认关闭时不输出 derived，所有上游已有提取器测试都要通过。

## 2. 模型理论通过路径
定位 Binwalk Rust 扫描入口、AnalysisResults 和配置开关。通过公开样本和正反清单逆向 BMP 像素位采样、帧同步、TLV、XOR、CRC、分片会话和跨载体贡献偏移。实现能够处理未见输入的通用恢复逻辑，而非固定样本输出；将真实载荷送入原签名引擎，并保持兼容。无需重写其他位宽 BMP 解析，也无需递归派生扫描。

## 3. Test 检查点依据
- Step 0：Cargo 文件哈希、无外部运行时依赖，对应题面约束。
- Step 1：`cargo test --offline --locked --lib --bins --tests` 覆盖全部既有库/二进制/集成测试（含旧版漏掉的 arj、cramfs、sevenzip、squashfs、squashfs_v2、yaffs2、zip、zip_truncated）。
- Step 2：Rust harness 编译，验证公开接口及输出字段。
- Step 3：21 个私有条目：case01 基线恢复；case07 位级错位；case08/09/44/56 TLV 和 XOR；case10/11/13/27/42 分片乱序、校验和冲突；case23/49 默认关闭；case24_include、case24_exclude 过滤；case26/48 损坏候选及正常后续帧；case37/40/53 跨载体比特相位；case41 帧内伪起始抑制。

verifier 在隔离环境内生成新鲜输入，核对完整 payload SHA-256、物理贡献偏移、流结构与可信扫描器签名行为。删除的用例对应不再要求的位深、额外 BMP 类型、递归和大规模压力范围，并非简单放宽仍写在题面中的要求。

## 4. 版本与实际试跑
原版 57 用例历史试跑和故障轨迹不能当成新版 pass@5。新题面与 Test 修改后，必须先做 Oracle 57/57 之外的新版全流程验证，随后完成 5 次干净的独立试跑；API/子代理故障不能计为模型能力失败。实际成功数和平均轮数尚待确认。
