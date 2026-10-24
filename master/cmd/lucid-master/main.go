package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SchearLoe/lucidnet/master"
)

// lucid-master —— 集群管理控制面（docs/dd/07）。
// 环境变量配置（LUCID_MASTER_*，docs/11 §8）；无本地配置文件。
func main() {
	showEnv := flag.Bool("env", false, "print effective options and exit")
	flag.Parse()

	opts := master.FromEnv()
	if *showEnv {
		log.Printf(`{"module":"lucid-master","opts":{%s}}`, optsString(opts))
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := master.New(opts)
	if err != nil {
		log.Fatalf(`{"level":"fatal","module":"lucid-master","msg":"bootstrap","err":%q}`, err.Error())
	}
	if err := srv.Run(ctx); err != nil {
		log.Fatalf(`{"level":"fatal","module":"lucid-master","msg":"run","err":%q}`, err.Error())
	}
}

func optsString(o master.Options) string {
	etcd := "[]"
	if len(o.EtcdEndpoints) > 0 {
		etcd = `"` + join(o.EtcdEndpoints) + `"`
	}
	kafka := "[]"
	if len(o.KafkaBrokers) > 0 {
		kafka = `"` + join(o.KafkaBrokers) + `"`
	}
	pg := "memory"
	if o.PGDSN != "" {
		pg = "dsn(redacted)"
	}
	return `"grpc":"` + o.GrpcAddr + `","http":"` + o.HTTPAddr +
		`","etcd":` + etcd + `,"kafka":` + kafka + `,"pg":"` + pg + `"`
}

func join(vs []string) string {
	out := ""
	for i, v := range vs {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
