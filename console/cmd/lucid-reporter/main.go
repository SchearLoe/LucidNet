// lucid-reporter —— R8 报表渲染与分发服务（docs/dd/05 §4）。
//
// M3 里程碑占位：当前仅编译占位，启动即提示未实现并退出（避免静默空跑）。
// 规划见 internal/report 包注释。
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "lucid-reporter: R8 报表服务属 M3 里程碑，尚未实现（docs/dd/05 §4；规划见 console/internal/report）")
	os.Exit(2)
}
