CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  object_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  delete_token TEXT NOT NULL,
  download_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at);

CREATE TABLE IF NOT EXISTS uploads (
  upload_id TEXT PRIMARY KEY,
  file_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  original_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  delete_token TEXT NOT NULL,
  expected_size INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_uploads_created_at ON uploads(created_at);

CREATE TABLE IF NOT EXISTS file_codes (
  file_id TEXT PRIMARY KEY,
  access_code TEXT NOT NULL UNIQUE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_file_codes_access_code ON file_codes(access_code);
