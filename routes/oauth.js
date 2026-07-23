const express = require('express')
const db = require('../db')
const getOAuthProvider = require('../config/oauthProviders')
const createOAuthTransaction = require('../utils/pkce')
const {
  createAccessToken,
  createRefreshToken,
  getRefreshTokenExpiration,
  setAuthCookies
} = require('../utils/tokens')

const router = express.Router()
const OAUTH_TRANSACTION_TTL_MS = 10 * 60 * 1000

const redirectToError = (res, reason) => {
  res.redirect(`/oauth-error.html?reason=${encodeURIComponent(reason)}`)
}

const fetchProfile = async (provider, accessToken) => {
  const headers = {
    Accept: 'application/json',
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'Batcave-OAuth'
  }
  const profileResponse = await fetch(provider.profileUrl, { headers })

  if (!profileResponse.ok) {
    throw new Error(`Profil ${provider.name} inaccessible.`)
  }

  const profile = await profileResponse.json()

  if (provider.name === 'google') {
    return {
      id: profile.sub,
      email: profile.email,
      displayName: profile.name || profile.email,
      avatarUrl: profile.picture
    }
  }

  if (provider.name === 'facebook') {
    return {
      id: profile.id,
      email: profile.email,
      displayName: profile.name,
      avatarUrl: profile.picture?.data?.url
    }
  }

  let email = profile.email

  if (!email) {
    const emailsResponse = await fetch(provider.emailsUrl, { headers })

    if (emailsResponse.ok) {
      const emails = await emailsResponse.json()
      const selectedEmail =
        emails.find(item => item.primary && item.verified) ||
        emails.find(item => item.verified)
      email = selectedEmail?.email
    }
  }

  return {
    id: String(profile.id),
    email,
    displayName: profile.name || profile.login,
    avatarUrl: profile.avatar_url
  }
}

const upsertOAuthUser = (provider, profile) => {
  const username = `${provider}_${profile.id}`

  return db
    .prepare(
      `
      INSERT INTO users (
        username,
        password_hash,
        two_factor_enabled,
        provider,
        provider_user_id,
        email,
        display_name,
        avatar_url
      )
      VALUES (?, NULL, 1, ?, ?, ?, ?, ?)
      ON CONFLICT(provider, provider_user_id) DO UPDATE SET
        email = excluded.email,
        display_name = excluded.display_name,
        avatar_url = excluded.avatar_url
      RETURNING *
    `
    )
    .get(
      username,
      provider,
      profile.id,
      profile.email || null,
      profile.displayName || username,
      profile.avatarUrl || null
    )
}

router.get('/:provider', (req, res) => {
  const provider = getOAuthProvider(req.params.provider)

  if (!provider?.clientId || !provider.clientSecret) {
    return redirectToError(res, 'configuration')
  }

  db.prepare('DELETE FROM oauth_transactions WHERE expires_at <= ?').run(
    Date.now()
  )

  const { state, codeVerifier, codeChallenge } = createOAuthTransaction()

  db.prepare(
    `
    INSERT INTO oauth_transactions (state, provider, code_verifier, expires_at)
    VALUES (?, ?, ?, ?)
  `
  ).run(
    state,
    provider.name,
    codeVerifier,
    Date.now() + OAUTH_TRANSACTION_TTL_MS
  )

  const authorizationUrl = new URL(provider.authorizationUrl)
  authorizationUrl.search = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: provider.callbackUrl,
    response_type: 'code',
    scope: provider.scopes.join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  })

  res.redirect(authorizationUrl.toString())
})

router.get('/:provider/callback', async (req, res) => {
  const provider = getOAuthProvider(req.params.provider)
  const state = typeof req.query.state === 'string' ? req.query.state : ''

  if (req.query.error) {
    if (state) {
      db.prepare(
        'DELETE FROM oauth_transactions WHERE state = ? AND provider = ?'
      ).run(state, req.params.provider)
    }

    return redirectToError(res, 'access_denied')
  }

  const code = typeof req.query.code === 'string' ? req.query.code : ''

  if (!provider?.clientId || !provider.clientSecret || !state || !code) {
    return redirectToError(res, 'invalid_callback')
  }

  const transaction = db
    .prepare(
      `
      SELECT * FROM oauth_transactions
      WHERE state = ? AND provider = ? AND expires_at > ?
    `
    )
    .get(state, provider.name, Date.now())

  db.prepare('DELETE FROM oauth_transactions WHERE state = ?').run(state)

  if (!transaction) {
    return redirectToError(res, 'invalid_state')
  }

  try {
    const tokenResponse = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        code,
        redirect_uri: provider.callbackUrl,
        grant_type: 'authorization_code',
        code_verifier: transaction.code_verifier
      })
    })
    const tokenData = await tokenResponse.json()

    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error('Échange du code OAuth impossible.')
    }

    const profile = await fetchProfile(provider, tokenData.access_token)

    if (!profile.id) {
      throw new Error('Identifiant fournisseur manquant.')
    }

    const user = upsertOAuthUser(provider.name, profile)
    const accessToken = createAccessToken({
      id: user.id,
      username: user.display_name || user.username
    })
    const refreshToken = createRefreshToken()

    db.prepare(
      `
      INSERT INTO refresh_tokens (user_id, token, expires_at)
      VALUES (?, ?, ?)
    `
    ).run(user.id, refreshToken, getRefreshTokenExpiration())

    setAuthCookies(res, accessToken, refreshToken)
    res.redirect('/bat-computer')
  } catch (error) {
    console.error(error.message)
    redirectToError(res, 'provider_error')
  }
})

module.exports = router
