// lucid-exporter —— 异步导出 worker（docs/dd/04 §5：任务模型 + 执行器骨架）
// + 查询/导出 HTTP API 空跑。
//
// walking skeleton：MemoryStore/MemoryProgressStore/MemoryCursorStore（Redis 桩）
// + SequenceSource（合成行源）+ Runner + export/query 两个 HTTP handler。
// -demo：创建并执行一个演示导出任务（产物打到 stdout），随后常驻 HTTP 直到信号。
// 真实 CH 流式读取 / MinIO 上传 / PG / Redis 接入 TODO 见模块 README。
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SchearLoe/lucidnet/storage/internal/export"
	"github.com/SchearLoe/lucidnet/storage/internal/query"
)

func main() {
	var (
		addr     = flag.String("addr", ":9152", "HTTP 监听地址（端口未在 dd/08 基线登记，TODO 待裁定）")
		demo     = flag.Bool("demo", false, "启动时执行一个演示导出任务（产物打 stdout）")
		demoRows = flag.Int("demo-rows", 20, "演示任务行数")
		format   = flag.String("format", "text", "演示任务格式 text|csv|jsonl")
	)
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// —— 桩组件组装（真实实现替换点见模块 README）——
	jobStore := export.NewMemoryStore(nil)
	progress := export.NewMemoryProgressStore()
	cursors := export.NewMemoryCursorStore()
	runner, err := export.NewRunner(jobStore, progress, cursors,
		export.NewSequenceSource(int64(*demoRows)),
		func(export.Job) (io.Writer, error) {
			return os.Stdout, nil
		})
	if err != nil {
		log.Fatalf("runner: %v", err)
	}

	// —— HTTP：查询 + 导出任务 API（经网关路由，docs/09 §6）——
	mux := http.NewServeMux()
	mux.Handle("/api/v1/flows/", query.NewSearchHandler(query.NewBuilder()).Routes())
	mux.Handle("/api/v1/export/", export.NewAPIHandler(jobStore).Routes())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Addr: *addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx) // 优雅退出：排空在途请求
	}()

	if *demo {
		if err := runDemo(ctx, jobStore, runner, export.Format(*format)); err != nil {
			log.Fatalf("demo: %v", err)
		}
	}

	log.Printf("lucid-exporter: http=%s stub=memory-store/sequence-source", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http: %v", err)
	}
	log.Printf("lucid-exporter exit")
}

// runDemo —— 演示任务：R5 攻击取证预填语义（zone + 窗口 + 过滤）。
func runDemo(ctx context.Context, store *export.MemoryStore, runner *export.Runner, format export.Format) error {
	now := time.Now().Unix()
	dstPort := uint32(443)
	job := export.Job{
		ID: "job-demo-0001", Type: export.JobFlows,
		ZoneID: 101, ZoneName: "客户A",
		TimeStart: now - 600, TimeEnd: now,
		Format:  format,
		Sample:  "raw",
		Filters: query.Filters{DstPort: &dstPort, ZoneID: int32Ptr(101)},
		Status:  export.StatusQueued,
	}
	if err := store.Create(ctx, job); err != nil {
		return err
	}
	log.Printf("demo job created: %s format=%s", job.ID, job.Format)
	if err := runner.Run(ctx, job.ID); err != nil {
		return err
	}
	final, err := store.Get(ctx, job.ID)
	if err != nil {
		return err
	}
	log.Printf("demo job final: status=%s progress=%.2f url=%s expires_at=%d",
		final.Status, final.Progress, final.URL, final.ExpiresAt)
	return nil
}

func int32Ptr(v int32) *int32 { return &v }
