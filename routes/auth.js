const express = require('express')
const bcrypt = require('bcrypt')
const db = require('../db')

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

  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send('Identifiants invalides')
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).send('Erreur serveur.')
    }

    req.session.user = {
      id: user.id,
      username: user.username
    }

    req.session.save(saveErr => {
      if (saveErr) {
        return res.status(500).send('Erreur serveur.')
      }

      res.redirect('/bat-computer')
    })
  })
})

router.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Erreur serveur.')
    }

    res.clearCookie('bat_identity')
    res.redirect('/auth/login')
  })
})

module.exports = router
