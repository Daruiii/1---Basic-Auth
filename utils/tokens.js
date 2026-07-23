const crypto = require('crypto')
const jwt = require('jsonwebtoken')

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60
const MFA_CHALLENGE_TTL_SECONDS = 5 * 60
const REFRESH_TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000

const cookieOptions = {
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production',
  path: '/'
}

const createAccessToken = user =>
  jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL_SECONDS }
  )

const createRefreshToken = () => crypto.randomBytes(64).toString('hex')

const getRefreshTokenExpiration = () => Date.now() + REFRESH_TOKEN_TTL_MS

const createMfaChallenge = user =>
  jwt.sign(
    { id: user.id, username: user.username, purpose: 'login-2fa' },
    process.env.JWT_SECRET,
    { expiresIn: MFA_CHALLENGE_TTL_SECONDS }
  )

const verifyMfaChallenge = token =>
  jwt.verify(token, process.env.JWT_SECRET)

const setAccessTokenCookie = (res, accessToken) => {
  res.cookie('accessToken', accessToken, {
    ...cookieOptions,
    maxAge: ACCESS_TOKEN_TTL_SECONDS * 1000
  })
}

const setAuthCookies = (res, accessToken, refreshToken) => {
  setAccessTokenCookie(res, accessToken)
  res.cookie('refreshToken', refreshToken, {
    ...cookieOptions,
    maxAge: REFRESH_TOKEN_TTL_MS
  })
}

const clearAuthCookies = res => {
  res.clearCookie('accessToken', cookieOptions)
  res.clearCookie('refreshToken', cookieOptions)
}

const setMfaChallengeCookie = (res, challenge) => {
  res.cookie('mfaChallenge', challenge, {
    ...cookieOptions,
    maxAge: MFA_CHALLENGE_TTL_SECONDS * 1000
  })
}

const clearMfaChallengeCookie = res => {
  res.clearCookie('mfaChallenge', cookieOptions)
}

module.exports = {
  createAccessToken,
  createRefreshToken,
  createMfaChallenge,
  verifyMfaChallenge,
  getRefreshTokenExpiration,
  setAccessTokenCookie,
  setAuthCookies,
  clearAuthCookies,
  setMfaChallengeCookie,
  clearMfaChallengeCookie
}
