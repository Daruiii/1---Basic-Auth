const createAuthorizationUrl = (
  provider,
  { state, codeChallenge }
) => {
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

  return authorizationUrl.toString()
}

const exchangeAuthorizationCode = async (
  provider,
  code,
  codeVerifier
) => {
  const response = await fetch(provider.tokenUrl, {
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
      code_verifier: codeVerifier
    })
  })
  const tokenData = await response.json()

  if (!response.ok || !tokenData.access_token) {
    throw new Error('Échange du code OAuth impossible.')
  }

  return tokenData.access_token
}

const createProfileHeaders = accessToken => ({
  Accept: 'application/json',
  Authorization: `Bearer ${accessToken}`,
  'User-Agent': 'Batcave-OAuth'
})

const fetchProviderProfile = async (provider, accessToken) => {
  const headers = createProfileHeaders(accessToken)
  const response = await fetch(provider.profileUrl, { headers })

  if (!response.ok) {
    throw new Error(`Profil ${provider.name} inaccessible.`)
  }

  const profile = await response.json()

  if (provider.name === 'github' && !profile.email) {
    const emailsResponse = await fetch(provider.emailsUrl, { headers })

    if (emailsResponse.ok) {
      const emails = await emailsResponse.json()
      const selectedEmail =
        emails.find(email => email.primary && email.verified) ||
        emails.find(email => email.verified)
      profile.email = selectedEmail?.email
    }
  }

  return profile
}

const normalizeProfile = (provider, profile) => {
  if (provider === 'google') {
    return {
      id: profile.sub,
      email: profile.email,
      displayName: profile.name || profile.email,
      avatarUrl: profile.picture
    }
  }

  if (provider === 'facebook') {
    return {
      id: profile.id,
      email: profile.email,
      displayName: profile.name,
      avatarUrl: profile.picture?.data?.url
    }
  }

  return {
    id: String(profile.id),
    email: profile.email,
    displayName: profile.name || profile.login,
    avatarUrl: profile.avatar_url
  }
}

const authenticateWithProvider = async (
  provider,
  code,
  codeVerifier
) => {
  const accessToken = await exchangeAuthorizationCode(
    provider,
    code,
    codeVerifier
  )
  const providerProfile = await fetchProviderProfile(provider, accessToken)
  const profile = normalizeProfile(provider.name, providerProfile)

  if (!profile.id) {
    throw new Error('Identifiant fournisseur manquant.')
  }

  return profile
}

module.exports = {
  createAuthorizationUrl,
  authenticateWithProvider
}
