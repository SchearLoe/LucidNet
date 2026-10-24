module github.com/SchearLoe/lucidnet/console

go 1.27

require (
	github.com/SchearLoe/lucidnet/shared v0.0.0
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/gorilla/websocket v1.5.3
	github.com/twmb/franz-go v1.22.2
)

require (
	github.com/alicebob/miniredis/v2 v2.40.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/pierrec/lz4/v4 v4.1.33 // indirect
	github.com/redis/go-redis/v9 v9.23.0 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.15.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/SchearLoe/lucidnet/shared => ../shared
