const express = require('express')
const bcrypt = require('bcrypt')
const qrcode = require('qrcode')
const { authenticator } = require('@otplib/preset-v11')
const db = require('../db')
const checkJWT = require('../middlewares/authCheck')
const {
  createAccessToken,
  createRefreshToken,
  verifyMfaChallenge,
  getRefreshTokenExpiration,
  setAccessTokenCookie,
  setAuthCookies,
  clearMfaChallengeCookie,
  clearAuthCookies
} = require('../utils/tokens')

const router = express.Router()

const strongPasswordPattern =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d\s])\S{12,}$/

const findUserByCredentials = async (username, password) => {
  if (!username || !password) {
    return null
  }

  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username.trim())

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return null
  }

  return user
}

router.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.cookies

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token manquant.' })
  }

  const storedToken = db
    .prepare(
      `
      SELECT refresh_tokens.*, users.username
      FROM refresh_tokens
      JOIN users ON users.id = refresh_tokens.user_id
      WHERE refresh_tokens.token = ?
    `
    )
    .get(refreshToken)

  if (!storedToken || storedToken.expires_at <= Date.now()) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken)
    clearAuthCookies(res)
    return res.status(401).json({ error: 'Refresh token invalide ou expiré.' })
  }

  const accessToken = createAccessToken({
    id: storedToken.user_id,
    username: storedToken.username
  })

  setAccessTokenCookie(res, accessToken)
  res.json({ message: 'Access token renouvelé.' })
})

router.post('/auth/change-password', checkJWT, async (req, res) => {
  const { currentPassword, newPassword } = req.body
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)

  const currentPasswordIsValid =
    user && (await bcrypt.compare(currentPassword || '', user.password_hash))

  if (!currentPasswordIsValid) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect.' })
  }

  if (!strongPasswordPattern.test(newPassword || '')) {
    return res.status(400).json({
      error:
        'Le nouveau mot de passe doit contenir 12 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.'
    })
  }

  const passwordHash = await bcrypt.hash(newPassword, 10)
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
    passwordHash,
    user.id
  )

  res.json({ message: 'Mot de passe modifié.' })
})

router.post('/auth/2fa/setup', async (req, res) => {
  const { username, password } = req.body
  const user = await findUserByCredentials(username, password)

  if (!user) {
    return res.status(401).json({ error: 'Premier facteur invalide.' })
  }

  if (user.two_factor_enabled) {
    return res.status(409).json({ error: 'La 2FA est déjà activée.' })
  }

  const secret = authenticator.generateSecret()
  const otpAuthUri = authenticator.keyuri(user.username, 'Batcave', secret)
  const qrCode = await qrcode.toDataURL(otpAuthUri)

  db.prepare(
    `
    UPDATE users
    SET two_factor_secret = ?, two_factor_enabled = 0
    WHERE id = ?
  `
  ).run(secret, user.id)

  res.json({ qrCode, secret })
})

router.post('/auth/2fa/confirm', (req, res) => {
  const username = req.body.username?.trim()
  const code = String(req.body.code || '')
  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)

  if (
    !user?.two_factor_secret ||
    !/^\d{6}$/.test(code) ||
    !authenticator.check(code, user.two_factor_secret)
  ) {
    return res.status(401).json({ error: 'Code 2FA invalide ou expiré.' })
  }

  db.prepare(
    'UPDATE users SET two_factor_enabled = 1 WHERE id = ?'
  ).run(user.id)

  res.json({ message: 'Double authentification activée.' })
})

router.post('/verify-2fa', (req, res) => {
  const username = req.body.username?.trim()
  const code = String(req.body.code || '')
  const challengeToken = req.cookies.mfaChallenge
  let challenge

  try {
    challenge = verifyMfaChallenge(challengeToken)
  } catch (error) {
    clearMfaChallengeCookie(res)
    return res.status(401).json({ error: 'Challenge 2FA invalide ou expiré.' })
  }

  if (challenge.purpose !== 'login-2fa' || challenge.username !== username) {
    return res.status(401).json({ error: 'Challenge 2FA invalide.' })
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.id)

  if (
    !user?.two_factor_enabled ||
    !user.two_factor_secret ||
    !/^\d{6}$/.test(code) ||
    !authenticator.check(code, user.two_factor_secret)
  ) {
    return res.status(401).json({ error: 'Code 2FA invalide ou expiré.' })
  }

  const accessToken = createAccessToken(user)
  const refreshToken = createRefreshToken()

  db.prepare(
    `
    INSERT INTO refresh_tokens (user_id, token, expires_at)
    VALUES (?, ?, ?)
  `
  ).run(user.id, refreshToken, getRefreshTokenExpiration())

  clearMfaChallengeCookie(res)
  setAuthCookies(res, accessToken, refreshToken)
  res.json({ message: 'Connexion validée.' })
})

module.exports = router
