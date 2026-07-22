const express = require('express')
const path = require('path')
const bcrypt = require('bcrypt')
const db = require('../db')
const checkJWT = require('../middlewares/authCheck')

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

router.get('/bat-computer', (req, res) => {
  const filePath = path.join(__dirname, '..', 'private', 'bat-computer.html')
  res.sendFile(filePath)
})

router.get('/api/secrets', checkJWT, (req, res) => {
  res.json(gadgets)
})

router.get('/api/me', checkJWT, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username })
})

router.post('/api/reports', checkJWT, (req, res) => {
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

module.exports = router
