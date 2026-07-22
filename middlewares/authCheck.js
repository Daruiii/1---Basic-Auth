const jwt = require('jsonwebtoken')

const checkJWT = (req, res, next) => {
  const accessToken = req.cookies.accessToken

  if (!accessToken) {
    return res.status(401).json({ error: 'Access token manquant.' })
  }

  try {
    req.user = jwt.verify(accessToken, process.env.JWT_SECRET)
  } catch (error) {
    return res.status(401).json({ error: 'Access token invalide ou expiré.' })
  }

  next()
}

module.exports = checkJWT
