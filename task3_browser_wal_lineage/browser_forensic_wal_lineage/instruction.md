# 浏览器 SQLite 取证：恢复 WAL 中的已提交历史快照

浏览器的 History、Cookies 等 SQLite 证据通常包含数据库主文件和 `-wal` 边车文件。现有 `browser-forensic-core` 可访问当前数据库视图，但无法向取证人员提供 WAL 中可独立验证的、按提交顺序排列的历史数据库镜像。

请在固定版本的 `SecurityRonin/browser-forensic` 中完成公开接口 `browser_forensic_core::wal_lineage::inspect_wal_lineage(path: &Path) -> std::io::Result<Vec<WalCommit>>`。环境已提供可编译的接口类型和空实现。`path` 指向 SQLite 主文件；可选 WAL 路径为同名文件追加 `-wal`。

每个 `WalCommit` 包含：

- `end_frame: u32`：完成这次提交的 WAL 帧序号（从 1 开始）。
- `database_pages: u32`：该已提交视图的数据库页数。
- `sha256: String`：该视图完整数据库物理字节镜像的 SHA-256，小写 64 位十六进制。镜像由主文件页面与截至该提交可见的 WAL 页面版本构成，按页号顺序连续排列，长度等于 `database_pages × page_size`。

输出必须且仅能包含能由 SQLite 持久化文件格式证明已经提交的视图，依提交顺序输出。被撕裂、损坏、无效或属于旧 WAL 世代的残留字节不得产生额外提交；若证据只足以证明一个更早的已提交前缀，应保留该前缀。不存在可用 WAL 提交记录时返回空列表；主文件不存在或不是有效 SQLite 主文件时返回错误。

验收输入为小规模真实 SQLite 数据库与 WAL 证据，不涉及数据库页面的 SQL 行内容恢复。原始证据文件必须保持字节不变；现有 `browser-forensic-core` 行为必须兼容。验收环境离线，仅保证上游已有的构建依赖与工具可用。最终只根据恢复的提交历史及其字节镜像、异常输入行为和原有回归判定；实现方法及调试过程不限。
