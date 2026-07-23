const oauthProviders = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    profileUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email', 'profile']
  },
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    authorizationUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    profileUrl: 'https://api.github.com/user',
    emailsUrl: 'https://api.github.com/user/emails',
    scopes: ['read:user', 'user:email']
  },
  facebook: {
    clientId: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    authorizationUrl: 'https://www.facebook.com/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/oauth/access_token',
    // L'IA proposait une version Meta figée potentiellement obsolète; ces URLs suivent la version configurée par l'application Meta.
    profileUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture',
    scopes: ['public_profile', 'email']
  }
}

const getOAuthProvider = name => {
  const provider = oauthProviders[name]

  if (!provider) {
    return null
  }

  const baseUrl = (
    process.env.APP_BASE_URL || 'http://localhost:3000'
  ).replace(/\/+$/, '')

  return {
    ...provider,
    name,
    callbackUrl: `${baseUrl}/auth/oauth/${name}/callback`
  }
}

module.exports = getOAuthProvider
