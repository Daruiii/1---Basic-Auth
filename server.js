const express = require('express')
const bcrypt = require('bcrypt')
const fs = require('fs')
const path = require('path')
const db = require('./db')

const app = express()
app.use(express.json())
app.use(express.static('public'))

const PORT = 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})

const gadgets = [
  {
    name: 'Batarang',
    desc: 'Arme de jet silencieuse pour neutraliser à distance.',
    icon: 'fa-bullseye'
  },
  {
    name: 'Grapnel Gun',
    desc: 'Grappin motorisé pour atteindre rapidement les toits.',
    icon: 'fa-arrow-up'
  },
  {
    name: 'Smoke Pellets',
    desc: 'Capsules fumigènes pour disparaître en quelques secondes.',
    icon: 'fa-cloud'
  }
]

app.post('/register', async (req, res) => {
  const username = req.body.username?.trim()
  const { password } = req.body

  if (!username || /\s/.test(username)) {
    return res
      .status(400)
      .send("Le nom d'utilisateur est obligatoire et ne doit pas contenir d'espaces.")
  }

  if (!password || password.length < 8) {
    return res
      .status(400)
      .send('Le mot de passe doit contenir au moins 8 caractères.')
  }

  const hash = await bcrypt.hash(password, 10)

  try {
    const insert = db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    )
    insert.run(username, hash)
    res.status(201).send('Utilisateur créé avec succès !')
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).send("Erreur : l'utilisateur existe déjà.")
    }

    res.status(500).send('Erreur serveur.')
  }
})

const checkAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Administration"')
    return res.status(401).send('Authentification requise')
  }
  const base64 = authHeader.split(' ')[1]
  const credentials = Buffer.from(base64, 'base64').toString()
  const separatorIndex = credentials.indexOf(':')

  if (separatorIndex === -1) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Administration"')
    return res.status(401).send('Identifiants invalides')
  }

  const username = credentials.slice(0, separatorIndex)
  const password = credentials.slice(separatorIndex + 1)

  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)
  if (user && (await bcrypt.compare(password, user.password_hash))) {
    req.user = user
    req.authHeader = authHeader
    next()
  } else {
    return res.status(401).send('Identifiants invalides')
  }
}

app.get('/bat-computer', checkAuth, (req, res) => {
  const filePath = path.join(__dirname, 'private', 'bat-computer.html')
  const html = fs
    .readFileSync(filePath, 'utf8')
    .replace('__AUTH_HEADER__', JSON.stringify(req.authHeader))

  res.send(html)
})

app.get('/api/secrets', checkAuth, (req, res) => {
  res.json(gadgets)
})

app.get('/api/me', checkAuth, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username
  })
})

app.post('/api/reports', checkAuth, (req, res) => {
  const content = req.body.content?.trim()

  if (!content) {
    return res.status(400).send('Le rapport ne peut pas être vide.')
  }

  const report = db
    .prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)')
    .run(req.user.id, content)

  res.status(201).json({
    id: report.lastInsertRowid,
    content
  })
})
