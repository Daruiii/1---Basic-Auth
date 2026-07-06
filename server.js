require('dotenv').config({ quiet: true })

const express = require('express')
const session = require('express-session')
const authRouter = require('./routes/auth')
const batComputerRouter = require('./routes/batComputer')

// Créé du serveur Express
const app = express()
// Rend possible la lecture et l'écriture du JSON
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
// Ouvre les fichiers frontend non protégés
app.use(express.static('public'))

app.use(
  session({
    name: 'bat_identity',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      maxAge: 1800000
    }
  })
)

app.use('/auth', authRouter)
app.use('/', batComputerRouter)

// Lance le serveur en local, sur le port 3000
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
