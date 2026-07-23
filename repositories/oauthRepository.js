const db = require('../db')

const deleteExpiredTransactions = now => {
  db.prepare('DELETE FROM oauth_transactions WHERE expires_at <= ?').run(now)
}

const saveTransaction = ({
  state,
  provider,
  codeVerifier,
  expiresAt
}) => {
  db.prepare(
    `
    INSERT INTO oauth_transactions (state, provider, code_verifier, expires_at)
    VALUES (?, ?, ?, ?)
  `
  ).run(state, provider, codeVerifier, expiresAt)
}

const deleteTransaction = (state, provider) => {
  db.prepare(
    'DELETE FROM oauth_transactions WHERE state = ? AND provider = ?'
  ).run(state, provider)
}

const consumeTransaction = db.transaction((state, provider, now) => {
  const transaction = db
    .prepare(
      `
      SELECT * FROM oauth_transactions
      WHERE state = ? AND provider = ? AND expires_at > ?
    `
    )
    .get(state, provider, now)

  deleteTransaction(state, provider)
  return transaction
})

const upsertUser = (provider, profile) => {
  const username = `${provider}_${profile.id}`

  return db
    .prepare(
      `
      INSERT INTO users (
        username,
        password_hash,
        two_factor_enabled,
        provider,
        provider_user_id,
        email,
        display_name,
        avatar_url
      )
      VALUES (?, NULL, 1, ?, ?, ?, ?, ?)
      ON CONFLICT(provider, provider_user_id) DO UPDATE SET
        email = excluded.email,
        display_name = excluded.display_name,
        avatar_url = excluded.avatar_url
      RETURNING *
    `
    )
    .get(
      username,
      provider,
      profile.id,
      profile.email || null,
      profile.displayName || username,
      profile.avatarUrl || null
    )
}

const saveRefreshToken = (userId, token, expiresAt) => {
  db.prepare(
    `
    INSERT INTO refresh_tokens (user_id, token, expires_at)
    VALUES (?, ?, ?)
  `
  ).run(userId, token, expiresAt)
}

module.exports = {
  deleteExpiredTransactions,
  saveTransaction,
  deleteTransaction,
  consumeTransaction,
  upsertUser,
  saveRefreshToken
}
