require('dotenv').config({ quiet: true })

const express = require('express')
const session = require('express-session')
const authRouter = require('./routes/auth')
const batComputerRouter = require('./routes/batComputer')

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
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

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
