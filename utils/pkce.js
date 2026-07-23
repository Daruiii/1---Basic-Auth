const crypto = require('crypto')

const toBase64Url = value =>
  value
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

const createOAuthTransaction = () => {
  const state = toBase64Url(crypto.randomBytes(32))
  const codeVerifier = toBase64Url(crypto.randomBytes(64))
  const codeChallenge = toBase64Url(
    crypto.createHash('sha256').update(codeVerifier).digest()
  )

  return { state, codeVerifier, codeChallenge }
}

module.exports = createOAuthTransaction
