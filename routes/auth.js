const express = require('express')
const path = require('path')
const bcrypt = require('bcrypt')
const db = require('../db')
const {
  createMfaChallenge,
  setMfaChallengeCookie,
  clearMfaChallengeCookie,
  clearAuthCookies
} = require('../utils/tokens')

const router = express.Router()

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'login.html'))
})

router.post('/login', async (req, res) => {
  const username = req.body.username?.trim()
  const { password } = req.body

  if (!username || !password) {
    return res.status(401).json({ error: 'Identifiants invalides.' })
  }

  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Identifiants invalides.' })
  }

  const { refreshToken } = req.cookies

  if (refreshToken) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken)
  }

  clearAuthCookies(res)
  clearMfaChallengeCookie(res)

  if (!user.two_factor_enabled) {
    return res.status(403).json({
      error: 'Vous devez activer la double authentification.',
      requires2FASetup: true,
      username: user.username
    })
  }

  const challenge = createMfaChallenge(user)
  setMfaChallengeCookie(res, challenge)
  res.json({ requires2FA: true, username: user.username })
})

router.get('/logout', (req, res) => {
  const { refreshToken } = req.cookies

  if (refreshToken) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken)
  }

  clearAuthCookies(res)
  clearMfaChallengeCookie(res)
  res.redirect('/')
})

module.exports = router
