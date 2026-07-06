const express = require('express')
const fs = require('fs')
const path = require('path')
const bcrypt = require('bcrypt')
const db = require('../db')
const isAuthenticated = require('../middlewares/authCheck')

const router = express.Router()

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

router.post('/register', async (req, res) => {
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

router.get('/bat-computer', isAuthenticated, (req, res) => {
  const filePath = path.join(__dirname, '..', 'private', 'bat-computer.html')
  const html = fs
    .readFileSync(filePath, 'utf8')
    .replace('__USERNAME__', req.session.user.username)

  res.send(html)
})

router.get('/api/secrets', isAuthenticated, (req, res) => {
  res.json(gadgets)
})

router.get('/api/me', isAuthenticated, (req, res) => {
  res.json(req.session.user)
})

router.post('/api/reports', isAuthenticated, (req, res) => {
  const content = req.body.content?.trim()

  if (!content) {
    return res.status(400).send('Le rapport ne peut pas être vide.')
  }

  const report = db
    .prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)')
    .run(req.session.user.id, content)

  res.status(201).json({
    id: report.lastInsertRowid,
    content
  })
})

module.exports = router
