-- 0002：配置发布补偿队列（PG outbox，docs/dd/07 §1 "失败补偿重试队列"）。
-- 语义：etcd 发布失败 → 版本标 failed（集群只读保护）+ 落本表；后台指数退避重投，
-- 成功关单（status=done）或人工取消（status=cancelled）；Master 重启扫描 pending 继续。
-- 命名规范（docs/11 §7）：snake_case、业务表复数、uq_/idx_ 前缀。

CREATE TABLE IF NOT EXISTS config_outbox(
  id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL,                   -- etcd 作用域键（/lucid/zones 等，docs/09 §5）
  version BIGINT NOT NULL,               -- 对应 config_versions.version
  payload JSONB NOT NULL,                -- 配置快照（Envelope.Data 原文）
  required JSONB NOT NULL DEFAULT '[]',  -- ACK 目标节点（重投成功后恢复跟踪）
  status TEXT NOT NULL DEFAULT 'pending',  -- pending|done|cancelled
  attempt INT NOT NULL DEFAULT 0,          -- 已重试次数（退避输入）
  next_retry TIMESTAMPTZ NOT NULL DEFAULT now(), -- 下次重试时刻（指数退避）
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 同一作用域版本至多一条 pending 单
CREATE UNIQUE INDEX IF NOT EXISTS uq_config_outbox_scope_version
  ON config_outbox(scope, version) WHERE status = 'pending';
-- 到期扫描（后台重试循环按 next_retry 升序取批）
CREATE INDEX IF NOT EXISTS idx_config_outbox_next_retry
  ON config_outbox(next_retry) WHERE status = 'pending';
