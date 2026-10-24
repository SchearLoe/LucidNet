package enrich

// GeoResolver —— GeoIP 富化源（dd/02 §3.2）。
//
// TODO(geoip)：mmdb 全内存 mmap（v4/v6 单库，≈100ns/条）；
// 表内 v4 地址用 ::ffff: 映射 16B 表示（与 FlowRecord 一致）。
type GeoResolver interface {
	GeoID(ip [16]byte) uint32
}

// GeoStub —— Geo 打桩（mmdb 接入前的开发实现）：表内精确匹配，未命中 0。
// 表为启动期配置（镜像 mmdb 打开后只读的语义），Set 非并发安全。
type GeoStub struct {
	table map[[16]byte]uint32
}

// NewGeoStub —— 构造空表桩。
func NewGeoStub() *GeoStub { return &GeoStub{table: make(map[[16]byte]uint32)} }

// Set —— 注入一条精确地址 → geo_id（开发/测试用）。
func (g *GeoStub) Set(ip [16]byte, geoID uint32) { g.table[ip] = geoID }

// GeoID —— 精确匹配；未命中 0（Geo 未知）。
func (g *GeoStub) GeoID(ip [16]byte) uint32 { return g.table[ip] }
