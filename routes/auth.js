const express = require('express')
const bcrypt = require('bcrypt')
const db = require('../db')
const {
  createAccessToken,
  createRefreshToken,
  getRefreshTokenExpiration,
  setAuthCookies,
  clearAuthCookies
} = require('../utils/tokens')

const router = express.Router()

router.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="fr-FR">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Connexion</title>
        <link
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"
          rel="stylesheet"
        />
      </head>
      <body>
        <main class="container py-4">
          <h1>Connexion</h1>
          <form method="post" action="/auth/login">
            <label for="username" class="form-label">Nom d'utilisateur</label>
            <input id="username" name="username" class="form-control" required />

            <label for="password" class="form-label mt-2">Mot de passe</label>
            <input
              id="password"
              name="password"
              type="password"
              class="form-control"
              required
            />

            <button type="submit" class="btn btn-primary mt-3">
              Se connecter
            </button>
          </form>
          <a href="/register.html" class="d-block mt-3">Créer un compte</a>
        </main>
      </body>
    </html>
  `)
})

router.post('/login', async (req, res) => {
  const username = req.body.username?.trim()
  const { password } = req.body

  if (!username || !password) {
    return res.status(401).send('Identifiants invalides')
  }

  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send('Identifiants invalides')
  }

  const accessToken = createAccessToken(user)
  const refreshToken = createRefreshToken()

  db.prepare(
    `
    INSERT INTO refresh_tokens (user_id, token, expires_at)
    VALUES (?, ?, ?)
  `
  ).run(user.id, refreshToken, getRefreshTokenExpiration())

  setAuthCookies(res, accessToken, refreshToken)
  res.redirect('/bat-computer')
})

router.get('/logout', (req, res) => {
  const { refreshToken } = req.cookies

  if (refreshToken) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken)
  }

  clearAuthCookies(res)
  res.redirect('/auth/login')
})

module.exports = router
