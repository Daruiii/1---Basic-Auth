require('dotenv').config({ quiet: true })

const express = require('express')
const cookieParser = require('cookie-parser')
const authRouter = require('./routes/auth')
const apiAuthRouter = require('./routes/apiAuth')
const batComputerRouter = require('./routes/batComputer')

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static('public'))

app.use('/auth', authRouter)
app.use('/api/auth', apiAuthRouter)
app.use('/', batComputerRouter)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
