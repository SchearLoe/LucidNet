package master

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

// migrations/0001_master_mvp.sql —— Master 管辖 PG DDL（docs/09 §7 DDL 属主）。
// 仓库级 migrations/ 目录尚未建立（docs/11 §2），暂存模块内并在最终报告标注；
// 收敛后应整体迁往仓库根 migrations/。

//go:embed migrations/*.sql
var migrationFS embed.FS

// fsGlob 列出迁移文件（升序）。
func fsGlob() ([]string, error) {
	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("glob migrations: %w", err)
	}
	sort.Strings(entries)
	return entries, nil
}
