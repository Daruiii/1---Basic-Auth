const isAuthenticated = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).send(`
      <!DOCTYPE html>
      <html lang="fr-FR">
        <head>
          <meta charset="UTF-8" />
          <meta http-equiv="refresh" content="0; url=/auth/login" />
          <title>Authentification requise</title>
        </head>
        <body>
          <p>Authentification requise. Redirection vers la connexion.</p>
        </body>
      </html>
    `)
  }

  next()
}

module.exports = isAuthenticated
