CREATE TABLE IF NOT EXISTS admin_auth_failures (
  client TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (client, token_hash)
);

CREATE INDEX IF NOT EXISTS idx_admin_auth_failures_client_created
ON admin_auth_failures(client, created_at);
