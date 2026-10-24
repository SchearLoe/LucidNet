# gen/go —— proto 生成代码（禁止手改）

本目录全部由 `buf generate` 生成，配置在仓库根 `proto/buf.yaml` 与 `proto/buf.gen.yaml`。
任何手改都会在下次生成时被覆盖；修正请改 `proto/lucidnet/v1/*.proto` 后重新生成。

```
proto/lucidnet/v1/*.proto  --buf generate-->  gen/go/lucidnet/v1/*.pb.go + *_grpc.pb.go
```

- Go 模块：`github.com/SchearLoe/lucidnet/gen/go`
- 生成包：`github.com/SchearLoe/lucidnet/gen/go/lucidnet/v1`（包名 `lucidnetv1`，全部消息集中放置）
- 插件版本：protoc-gen-go v1.36.12、protoc-gen-go-grpc v1.6.2（`require_unimplemented_servers=false`）

## 权威关系（重要）

1. **根 proto（`proto/lucidnet/v1/`）是唯一权威**：接口语义以 docs/09 + docs/00 为准，
   线格式（消息、字段编号、gRPC 服务）以根 proto 为准。
2. `master/internal/masterpb/service.proto` 是根 `service.proto` 的**临时副本**
   （仅 `go_package` option 指向 master 模块不同，消息/服务逐字相同），
   是 gen/go 落地前 master 模块的自举产物。
3. **gen/go 已落地**：各模块应逐步从本地副本/手写镜像切换到
   `github.com/SchearLoe/lucidnet/gen/go/lucidnet/v1`；全部切换完成后删除 masterpb 临时副本，
   并保证 CI 中 `buf build` 持续通过。

## 重新生成

```bash
export PATH=$PATH:"$(go env GOPATH)/bin"
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
cd proto && buf generate
```
