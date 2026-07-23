const authFetch = async (url, options = {}) => {
  const requestOptions = { credentials: 'same-origin', ...options }
  let response = await fetch(url, requestOptions)

  if (response.status !== 401) {
    return response
  }

  console.log('Access token expiré : rafraîchissement en cours.')
  const refreshResponse = await fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'same-origin'
  })

  if (!refreshResponse.ok) {
    window.location.href = '/'
    return response
  }

  console.log('Access token renouvelé : rejeu de la requête.')
  response = await fetch(url, requestOptions)
  return response
}

const loadDashboard = async () => {
  const profileResponse = await authFetch('/api/me')

  if (!profileResponse.ok) {
    return
  }

  const user = await profileResponse.json()
  document.getElementById('welcome').textContent =
    `Bienvenue, Justicier ${user.username}`

  const gadgetsResponse = await authFetch('/api/secrets')
  const gadgetsContainer = document.getElementById('gadgets')

  if (!gadgetsResponse.ok) {
    gadgetsContainer.textContent = "Impossible de charger l'arsenal."
    return
  }

  const gadgets = await gadgetsResponse.json()
  gadgetsContainer.innerHTML = gadgets
    .map(
      gadget => `
        <article class="col-md-4">
          <div class="card h-100">
            <div class="card-body">
              <i class="fa-solid ${gadget.icon} fs-2 mb-3"></i>
              <h3 class="h5">${gadget.name}</h3>
              <p>${gadget.desc}</p>
            </div>
          </div>
        </article>
      `
    )
    .join('')
}

document.getElementById('report-form').onsubmit = async event => {
  event.preventDefault()

  const messageElement = document.getElementById('report-message')
  const reportElement = document.getElementById('report')
  const response = await authFetch('/api/reports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: reportElement.value })
  })

  messageElement.style.color = response.ok ? 'green' : 'red'
  messageElement.textContent = response.ok
    ? 'Rapport enregistré.'
    : "Erreur lors de l'enregistrement."

  if (response.ok) {
    reportElement.value = ''
  }
}

loadDashboard()
