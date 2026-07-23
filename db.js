const Database = require('better-sqlite3')
const db = new Database('auth_demo.db')

db.pragma('foreign_keys = ON')

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    two_factor_secret TEXT,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    provider TEXT,
    provider_user_id TEXT,
    email TEXT,
    display_name TEXT,
    avatar_url TEXT
  )
`
).run()

const userColumns = db.prepare('PRAGMA table_info(users)').all()

if (!userColumns.some(column => column.name === 'two_factor_secret')) {
  db.prepare('ALTER TABLE users ADD COLUMN two_factor_secret TEXT').run()
}

if (!userColumns.some(column => column.name === 'two_factor_enabled')) {
  db.prepare(
    'ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0'
  ).run()
}

const oauthUserColumns = {
  provider: 'TEXT',
  provider_user_id: 'TEXT',
  email: 'TEXT',
  display_name: 'TEXT',
  avatar_url: 'TEXT'
}

for (const [column, type] of Object.entries(oauthUserColumns)) {
  if (!userColumns.some(userColumn => userColumn.name === column)) {
    db.prepare(`ALTER TABLE users ADD COLUMN ${column} ${type}`).run()
  }
}

db.prepare(
  `
  CREATE UNIQUE INDEX IF NOT EXISTS users_provider_identity
  ON users (provider, provider_user_id)
`
).run()

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`
).run()

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`
).run()

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS oauth_transactions (
    state TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )
`
).run()

module.exports = db
