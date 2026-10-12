# binwalk_bmp_derived_stream：测试分析（2026-10-11 返修版）

本文对应当前任务包，不对应 jobs/2026-10-06__17-33-05 中的旧题面及旧 verifier。任务 ZIP、本文和新试跑的配对关系以 revision_manifest.json 为准。

## 1. 公开条件与交付契约

题面 instruction.md、现场笔记 environment/derived-bitmap-stream.md 以及 18 个公开样本及其 MANIFEST.md 是被测模型可以读取的材料。基线为 Binwalk commit 26713972e3f9f52dc37d4a421c4554b0bd9e82ef，Cargo 依赖预取，支持离线构建。

- 公开开关为 Binwalk::enable_derived_streams(bool)，默认关闭；关闭时原有扫描行为不变，JSON 不得出现 derived。
- 每个派生结果含 kind、stream_id、carrier_offsets、total_payload_size、公开的完整 payload: Vec<u8>、file_map 和可选 nested_derived。kind 为 bmp-fragmented-stream；载体偏移相对于直接父输入，升序去重；payload 数组长度等于 total_payload_size。
- 实际恢复载荷必须送入既有签名分析与验证流程，继承 include/exclude 过滤。子签名偏移相对于恢复载荷。
- 最外层扫描深度为 1，最大为 3；深度 4 及更深不得继续扫描或报告。完整 payload 和深度上限是当前题面明确要求，不是私有 verifier 新增的要求。
- 不得修改 Cargo.toml/Cargo.lock，不得引入外部运行时依赖或调用外部子进程，须保持既有测试通过。
- 公开样本清单声明正例的流编号、载荷长度、SHA-256、载体偏移和嵌套关系，负例声明应无结果。线格式需要通过样本逆向；以下协议结论不应误称为题面直接提供的字段定义。

## 2. 理论实现路径

### 2.1 库接入及载体采样

定位配置、AnalysisResults、scan/analyze_buf 接入点，增加默认关闭开关和派生结果类型。关闭或无结果时跳过序列化空 derived；每层保存实际载荷，调用原有扫描逻辑而非合成签名描述。

从样本验证 BMP 几何、边界、行方向和 padding。支持 DIB 40/108/124 字节头、单平面、24/32-bit BI_RGB、16-bit BI_RGB/BI_BITFIELDS。24/32-bit 采样 B/G/R 字节 bit 0，忽略 Alpha；16-bit BI_RGB 为 RGB555，位域取各通道掩码最低置位。按逻辑显示顺序采样，跳过四字节对齐行尾 padding。调色板、RLE、32-bit BI_BITFIELDS、越界几何等不支持载体不应产生结果。

合格载体按物理偏移升序无填充拼接采样比特，不在边界重置字节相位。记录各比特对应载体，计算跨载体帧贡献偏移。合格 BMP 内的伪 BM 不应重复采样。

### 2.2 帧格式与同步

当前样本和 tests/generate_cases.py 使用二进制魔数 b6 5a e3 81 0c f4 29 d8，不是 ASCII BWDERIV2。在比特流中滑动匹配 64 位魔数，后续字节 MSB-first 组装；数值字段为小端。下表偏移相对于帧起点：

| 偏移 | 字节数 | 字段 |
| --- | --- | --- |
| 0 | 8 | 二进制魔数 |
| 8 | 4 | StreamId |
| 12 | 2 | FragmentCount |
| 14 | 2 | FragmentIndex |
| 16 | 4 | FragmentLength |
| 20 | 4 | PayloadOffset |
| 24 | 4 | TotalLength |
| 28 | 4 | TotalCRC |
| 32 | 4 | FragmentCRC |
| 36 | 1 | Version，必须为 2 |
| 37 | 1 | Flags，必须为 0 |
| 38 | 2 | Reserved，必须为 0 |
| 40 | 4 | HeaderLength，至少 44 |
| 44 | 可变 | TLV，直到 HeaderLength |
| HeaderLength | FragmentLength | 编码后的分片 |

核心头连同魔数共 44 字节。TLV 为 tag/length/value；tag 1 为 1..16 字节循环 XOR 密钥，每个分片从密钥起点解扰；未知非关键扩展忽略，未知高位为 1 的关键扩展拒绝。检查版本、保留字段、头和载荷边界、索引/数量、非零长度、总载荷不超过 16 MiB；解扰后验证 IEEE CRC32 FragmentCRC。

合法帧作为不透明整体跳过，失败候选不吞噬后续潜在帧。魔数、头和载荷均可能跨载体边界。

### 2.3 重组、扫描与递归

按 (StreamId, TotalCRC, FragmentCount, TotalLength) 聚合会话，防止陈旧与新会话混用。分片序号唯一且覆盖 0..FragmentCount-1；相同内容重复分片也使会话无效。分片区间无重叠、无空洞地覆盖完整载荷，重组后校验 TotalCRC；只计入有效会话的贡献载体。

将真实载荷送入既有签名引擎，保存完整 payload，递归至深度 3。逐项与公开清单的完整载荷 SHA-256、偏移和嵌套关系核对，不能只验证识别出 ZIP/PNG。

## 3. 当前 verifier 实际校验及隔离

### 3.1 可信构建与低权限提交构建

测试镜像在安装提交前针对原始固定 commit 构建 trusted_signature_reference，并保存原始 Cargo 文件 SHA-256及可信二进制的动态依赖。可信扫描器不在提交后重新构建。

test.sh 的 root 监督进程初始化 reward 为 0，保护 /tests 和 reward 目录。提交的构建脚本、proc-macro、测试及 harness 编译均以 UID 10001、no-new-privileges 运行；构建前后检查 Cargo 哈希，构建使用 --offline --locked。预装 Kaleido 配置支持低权限离线编译。

源码的 process::Command/Command::new 搜索仅为启发式检查，不能单独证明没有外部调用。空 PATH 同样不是充分的安全隔离；真正的执行边界见下文。

### 3.2 完整 payload 与可信签名比较

完成不可信构建和回归之后，verify.py 才在 root 私有临时目录生成 57 个用例族。每次改变流编号、ZIP 内容、PNG 附加内容、不透明载荷字节和文件名。所有顶层及嵌套期望流必须有完整 expected_payload_sha256；缺失时报生成器错误，不能跳过。

validate_stream_entry 要求 payload 是长度正确的完整字节数组；元素严格为 int 而非 bool，值为 0..255，非空且不超过 16 MiB。verifier 将其转为字节后独立计算 SHA-256。SHA-256 是 256 位摘要，常用 64 个十六进制字符表示，不是“64 位摘要”。

随后以同一 include/exclude 配置运行可信固定版本 Binwalk，对完整 file_map 作比较：仅忽略每次随机生成的 UUID id，并规范化顺序；其他序列化签名字段全部比较。另核对子签名名称、偏移、大小、描述，以及实际 payload 切片的 expected_content_sha256。

当前 verifier 没有 expected_sha256_offset 校验，不把描述字符串中的摘要当作载荷完整性证据。最外层 file_map 同样与可信扫描比较，包括关闭派生模式时。流数量、类型、编号、载体偏移、长度及全部嵌套逐项核对；预期嵌套为空也必须检查，防止多报告深度 4。

### 3.3 隔离边界与限制

harness 从 stdin 获取输入，库只收到固定逻辑名称 input.bin，没有私有样本绝对路径。其执行进入全新 chroot，仅有提交 executable 与可信动态库；降为 UID/GID 65534、关闭继承描述符、设置 no-new-privileges。seccomp 禁止网络、创建进程和跨进程内存访问。没有样本、清单、生成器、构建树或 /proc，无法利用输入文件名读取旁边的答案。无法建立边界直接失败，无弱化回退。

每个执行限制为 CPU 15 秒、墙钟 20 秒、地址空间 2 GiB、输出 128 MiB。测试容器须以 root 运行且具备通常默认的 SYS_CHROOT 能力，不需要 privileged mode。

这些措施验证完整载荷与可观测签名行为，不能黑盒证明提交内部调用了某个唯一算法；不应排除其他正确实现。

## 4. 检查点及公开依据

| 检查点 | 用例 | 公开依据 |
| --- | --- | --- |
| 默认关闭、原签名行为不变 | case23、49；所有用例顶层 file_map | 题面兼容性要求 |
| 完整恢复、签名复用及过滤 | 所有有效流；case24_include/exclude | 当前题面 payload/签名要求 |
| 方向、padding、掩码与采样 | case01..06、30、33、47、50、54 | spec01..07、18 |
| 不支持及畸形载体拒绝 | case21、22、32、34、36、48、51、55 | spec17、18 的负例与边界安全 |
| 比特同步、TLV、XOR、CRC | case07..09、25、26、31、44、56 | spec01、11、15、17 |
| 多帧、分片与会话隔离 | case10..19、27、29、35、41、42、45、46、52 | spec08、12、13、15、17 |
| 跨载体相位和贡献偏移 | case37..40、53 | spec09、10、16 |
| 嵌套、深度和过滤继承 | case20、24_include/exclude、28、43 | spec14；题面明确深度 3 |
| 依赖、编译 API、上游回归 | test.sh Step 0..2 | 题面依赖、开关与兼容性要求 |

test.sh 实际执行库/二进制目标及 14 个选定上游集成测试目标：androidsparse、arcadyan、bmp、bzip2、csman、gzip、jpeg、matter_ota、mbr、pdf、png、qcow、riff、romfs。不要将此描述为已执行仓库所有可能的集成目标。

test_verify.py 的 14 项自检覆盖完整载荷、伪造签名、类型/嵌套、生成新鲜度，并以编译 C 探针实际验证文件系统、描述符、权限、网络和进程边界。它们是 verifier 自身安全回归，不代替目标模型试跑。

## 5. 试跑归因与提交规则

2026-10-06 的 5 次历史试跑中，3 次汇总标记为模型 API 错误，原始日志还出现子代理 model_not_found。另两次分别在公开 API 编译处失败、旧版 verifier 通过 53/57。其题面缺少当前 payload 和深度契约，verifier 也是旧版，因此这些 reward 不能作为当前包可靠的能力信号。

当前参考实现的 57/57、公开样本核对与隔离自检只说明参考解和测试可验收，不能替代目标模型 5 次真实试跑。新试跑应绑定冻结包哈希，留存脱敏配置、agent/子代理原始记录及 verifier 日志；API 故障单列，不改写为逆向能力失败。未完成新试跑时不得把旧 expert_trajectory.zip 或旧截图当作当前版本的证据上传。
