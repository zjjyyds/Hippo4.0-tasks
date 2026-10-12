# Hippo 4.0 高难度 Agentic Coding 评测任务集

本项目包含符合 Hippo 4.0 规范的高难度 Agentic Coding 自动化评测基准任务包，设计目标为考察前沿 SOTA 大模型在真实攻防安全、逆向工程与数字取证场景下的自主解决能力。

---

## 📁 任务索引

### 1. `binwalk_bmp_derived_stream`（第一题：固件位图派生数据流分析）
- **领域**：攻防安全 / Reverse Engineering / 固件隐写分析
- **目标仓库**：`ReFirmLabs/binwalk` (Rust v3, commit `26713972e3f9f52dc37d4a421c4554b0bd9e82ef`)
- **核心难点**：
  - 纯黑盒样本逆向推导（18 个生产样本与清单）
  - 跨载体亚字节非对齐比特缝合（Sub-Byte Bit Splicing）
  - 嵌套帧包含性与幽灵魔数抑制
  - 16-bit `BITMAPV4HEADER` / `BITMAPV5HEADER` 动态位域掩码采样
  - 多载体乱序重组与陈旧会话冲突隔离
  - 递归深度上限与 SHA-256 载荷摘要完整性校验
- **评测成绩**：`Pass@5 = 0/5`（平均交互轮数 > 500 轮，达到预期能力边界）
- **交付文件**：
  - `task1_binwalk_bmp_derived_stream/binwalk_bmp_derived_stream.zip`（任务包）
  - `task1_binwalk_bmp_derived_stream/expert_trajectory.zip`（标准化轨迹包）
  - `task1_binwalk_bmp_derived_stream/tests_analysis.md`（三段式 tests 分析）
  - `task1_binwalk_bmp_derived_stream/题目提交信息.md`（表单填写指引）

---

### 2. `hindsight_extension_worker_evidence_reconstruction`（第二题：浏览器扩展 Service Worker 跨快照状态重建）
- **领域**：攻防安全 / DFIR / 浏览器数字取证
- **目标仓库**：`RyanDFIR/hindsight` (Python, commit `25bfb163bdcbb095daf33d55f087cab9a086a23f`)
- **核心难点**：
  - 跨多快照 Chromium Service Worker LevelDB 与 ScriptCache 关联分析
  - 三态证据模型与不完整普查推导（确认缺席 ≠ 采集缺口）
  - 移除边界与邻接快照推论（首见 ≠ 创建）
  - 路径穿越安全与扩展根目录隔离
  - 信息单调性与证据降级机制
- **交付文件**：
  - `hindsight_extension_worker_evidence_reconstruction/`（任务包源码）
  - `hindsight_extension_worker_evidence_reconstruction.zip`（合规交付包）

---

## 🛠️ 本地运行与验证

```bash
# 验证第一题 Oracle（57 组测试全过）：
harbor run -p task1_binwalk_bmp_derived_stream/binwalk_bmp_derived_stream --agent oracle

# 验证第二题 Oracle（21 组测试全过）：
harbor run -p hindsight_extension_worker_evidence_reconstruction --agent oracle
```
