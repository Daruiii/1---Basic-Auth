require('dotenv').config({ quiet: true })

const express = require('express')
const cookieParser = require('cookie-parser')
const helmet = require('helmet')
const authRouter = require('./routes/auth')
const apiAuthRouter = require('./routes/apiAuth')
const batComputerRouter = require('./routes/batComputer')

const app = express()
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://cdn.jsdelivr.net',
          'https://cdnjs.cloudflare.com'
        ],
        scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
        fontSrc: ["'self'", 'https://cdnjs.cloudflare.com'],
        imgSrc: ["'self'", 'data:']
      }
    }
  })
)
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static('public'))

app.use('/auth', authRouter)
app.use('/api', apiAuthRouter)
app.use('/', batComputerRouter)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
