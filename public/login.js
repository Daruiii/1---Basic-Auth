const loginForm = document.getElementById('login-form')
const setupSection = document.getElementById('setup-section')
const verifySection = document.getElementById('verify-section')
const messageElement = document.getElementById('message')

let pendingUsername = ''
let pendingPassword = ''

const readResponse = async response => {
  const contentType = response.headers.get('content-type') || ''

  if (contentType.includes('application/json')) {
    return response.json()
  }

  return { error: await response.text() }
}

const showMessage = (message, isError = false) => {
  messageElement.style.color = isError ? 'red' : 'green'
  messageElement.textContent = message
}

loginForm.onsubmit = async event => {
  event.preventDefault()

  pendingUsername = document.getElementById('username').value.trim()
  pendingPassword = document.getElementById('password').value

  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: pendingUsername,
      password: pendingPassword
    })
  })
  const result = await readResponse(response)

  if (response.status === 403 && result.requires2FASetup) {
    const setupResponse = await fetch('/api/auth/2fa/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: pendingUsername,
        password: pendingPassword
      })
    })
    const setup = await readResponse(setupResponse)

    if (!setupResponse.ok) {
      showMessage(setup.error, true)
      return
    }

    document.getElementById('qr-code').src = setup.qrCode
    document.getElementById('secret').textContent = setup.secret
    loginForm.hidden = true
    setupSection.hidden = false
    showMessage('Scannez le QR Code puis saisissez le code généré.')
    return
  }

  if (response.ok && result.requires2FA) {
    loginForm.hidden = true
    verifySection.hidden = false
    showMessage('Saisissez le code de votre application.')
    return
  }

  showMessage(result.error || 'Connexion impossible.', true)
}

document.getElementById('setup-form').onsubmit = async event => {
  event.preventDefault()

  const response = await fetch('/api/auth/2fa/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: pendingUsername,
      code: document.getElementById('setup-code').value
    })
  })
  const result = await readResponse(response)

  if (!response.ok) {
    showMessage(result.error, true)
    return
  }

  setupSection.hidden = true
  loginForm.hidden = false
  loginForm.reset()
  pendingPassword = ''
  showMessage('2FA activée. Connectez-vous à nouveau.')
}

document.getElementById('verify-form').onsubmit = async event => {
  event.preventDefault()

  const response = await fetch('/api/verify-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: pendingUsername,
      code: document.getElementById('verify-code').value
    })
  })
  const result = await readResponse(response)

  if (!response.ok) {
    showMessage(result.error, true)
    return
  }

  window.location.href = '/bat-computer'
}
