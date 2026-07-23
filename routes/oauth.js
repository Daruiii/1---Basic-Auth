const express = require('express')
const getOAuthProvider = require('../config/oauthProviders')
const oauthRepository = require('../repositories/oauthRepository')
const {
  createAuthorizationUrl,
  authenticateWithProvider
} = require('../services/oauthService')
const createPkceTransaction = require('../utils/pkce')
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

router.get('/:provider', (req, res) => {
  const provider = getOAuthProvider(req.params.provider)

  if (!provider?.clientId || !provider.clientSecret) {
    return redirectToError(res, 'configuration')
  }

  oauthRepository.deleteExpiredTransactions(Date.now())

  const { state, codeVerifier, codeChallenge } = createPkceTransaction()

  oauthRepository.saveTransaction({
    state,
    provider: provider.name,
    codeVerifier,
    expiresAt: Date.now() + OAUTH_TRANSACTION_TTL_MS
  })

  const authorizationUrl = createAuthorizationUrl(provider, {
    state,
    codeChallenge
  })

  res.redirect(authorizationUrl)
})

router.get('/:provider/callback', async (req, res) => {
  const provider = getOAuthProvider(req.params.provider)
  const state = typeof req.query.state === 'string' ? req.query.state : ''

  if (req.query.error) {
    if (state) {
      oauthRepository.deleteTransaction(state, req.params.provider)
    }

    return redirectToError(res, 'access_denied')
  }

  const code = typeof req.query.code === 'string' ? req.query.code : ''

  if (!provider?.clientId || !provider.clientSecret || !state || !code) {
    return redirectToError(res, 'invalid_callback')
  }

  const transaction = oauthRepository.consumeTransaction(
    state,
    provider.name,
    Date.now()
  )

  if (!transaction) {
    return redirectToError(res, 'invalid_state')
  }

  try {
    const profile = await authenticateWithProvider(
      provider,
      code,
      transaction.code_verifier
    )
    const user = oauthRepository.upsertUser(provider.name, profile)
    const accessToken = createAccessToken({
      id: user.id,
      username: user.display_name || user.username
    })
    const refreshToken = createRefreshToken()

    oauthRepository.saveRefreshToken(
      user.id,
      refreshToken,
      getRefreshTokenExpiration()
    )

    setAuthCookies(res, accessToken, refreshToken)
    res.redirect('/bat-computer')
  } catch (error) {
    console.error(error.message)
    redirectToError(res, 'provider_error')
  }
})

module.exports = router
