const express = require('express')
const bcrypt = require('bcrypt')
const db = require('../db')
const checkJWT = require('../middlewares/authCheck')
const {
  createAccessToken,
  setAccessTokenCookie,
  clearAuthCookies
} = require('../utils/tokens')

const router = express.Router()

const strongPasswordPattern =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d\s])\S{12,}$/

router.post('/refresh', (req, res) => {
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

router.post('/change-password', checkJWT, async (req, res) => {
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

module.exports = router
