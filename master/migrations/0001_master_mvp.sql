-- LucidMaster MVP DDL（docs/dd/07 §2/§4/§5；docs/09 §7：DDL 属主一律 Master）
-- 命名规范（docs/11 §7）：表/列 snake_case，业务表复数；索引 idx_<表>_<列>；外键不建物理约束。

-- 节点档案（docs/dd/07 §2）
CREATE TABLE IF NOT EXISTS nodes(
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL,                    -- broker|collector|analytics|storage|master|bgp
  host TEXT NOT NULL DEFAULT '',
  cores INT NOT NULL DEFAULT 0,
  mem_gb INT NOT NULL DEFAULT 0,
  nics JSONB NOT NULL DEFAULT '[]',      -- [{"name":"eth0","speed_gbps":25000}]
  state TEXT NOT NULL DEFAULT 'online',  -- online|draining|maintenance|offline
  degraded BOOLEAN NOT NULL DEFAULT FALSE,
  version TEXT NOT NULL DEFAULT '',
  weight_override DOUBLE PRECISION NOT NULL DEFAULT 0, -- >0 覆盖自动权重
  joined_at TIMESTAMPTZ,
  last_hb TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_nodes_state ON nodes(state);

-- exporter 台账（分配算法输入，docs/dd/07 §3）
CREATE TABLE IF NOT EXISTS exporters(
  ip TEXT PRIMARY KEY,
  device_id BIGINT NOT NULL DEFAULT 0,
  last_seen TIMESTAMPTZ,
  rate_fps DOUBLE PRECISION NOT NULL DEFAULT 0,
  pinned_collector TEXT NOT NULL DEFAULT '',
  active_set BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_exporters_last_seen ON exporters(last_seen);

-- 租户（docs/dd/07 §4）
CREATE TABLE IF NOT EXISTS tenants(
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 用户（tenant_id=0 为平台级账号，租户隔离豁免）
CREATE TABLE IF NOT EXISTS users(
  id BIGSERIAL PRIMARY KEY,
  tenant_id BIGINT NOT NULL DEFAULT 0,
  name TEXT NOT NULL UNIQUE,
  passwd_hash TEXT NOT NULL,
  is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 角色（权限点 JSONB，docs/dd/07 §4；tenant_id=0 为预置模板）
CREATE TABLE IF NOT EXISTS roles(
  id BIGSERIAL PRIMARY KEY,
  tenant_id BIGINT NOT NULL DEFAULT 0,
  name TEXT NOT NULL,
  perms JSONB NOT NULL DEFAULT '[]',
  preset BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS user_roles(
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY(user_id, role_id)
);

-- 配置版本（PG 权威快照 → etcd 分发，docs/dd/07 §5；保留最近 20 版）
CREATE TABLE IF NOT EXISTS config_versions(
  id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL,                   -- /lucid/zones | /lucid/forward/rules | ...
  version BIGINT NOT NULL,
  state TEXT NOT NULL,                   -- published|active|partial|failed|rolled_back
  data JSONB NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ack_summary JSONB NOT NULL DEFAULT '{}',
  rollback_of BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_config_versions_scope_version
  ON config_versions(scope, version);
CREATE INDEX IF NOT EXISTS idx_config_versions_scope ON config_versions(scope, version DESC);

-- 审计（docs/hld/07 §4：who/when/diff/ip）
CREATE TABLE IF NOT EXISTS audit_log(
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_name TEXT NOT NULL DEFAULT '',
  tenant TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  resource TEXT NOT NULL DEFAULT '',
  diff JSONB NOT NULL DEFAULT '{}',
  ip TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'user', -- user|system
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_name, ts DESC);

-- 版本兼容矩阵（docs/dd/07 §6；升级编排属 08 LucidDeploy，Master 仅持表）
CREATE TABLE IF NOT EXISTS upgrade_matrix(
  from_version TEXT NOT NULL,
  to_version TEXT NOT NULL,
  migrate_script TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(from_version, to_version)
);
