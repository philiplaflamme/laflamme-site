export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Handle contact form POST
    if (url.pathname === '/api/contact' && request.method === 'POST') {
      return handleContact(request, env);
    }

    // Everything else → static assets
    return env.ASSETS.fetch(request);
  }
};

async function handleContact(request, env) {
  const headers = { 'Content-Type': 'application/json' };

  try {
    const data = await request.formData();
    const prenom = data.get('prenom') || '';
    const nom = data.get('nom') || '';
    const email = data.get('email') || '';
    const service = data.get('service') || '';
    const message = data.get('message') || '';

    // Basic validation
    if (!prenom || !email || !message) {
      return new Response(
        JSON.stringify({ error: 'Missing required fields' }),
        { status: 400, headers }
      );
    }

    const fullName = nom ? `${prenom} ${nom}` : prenom;

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `Site dupuislaflamme.ca <noreply@dupuislaflamme.ca>`,
        to: ['info@laflamme.me'],
        reply_to: email,
        subject: `Nouveau message de ${fullName}`,
        html: `
          <h2>Nouveau message via dupuislaflamme.ca</h2>
          <p><strong>Nom:</strong> ${escapeHtml(fullName)}</p>
          <p><strong>Courriel:</strong> ${escapeHtml(email)}</p>
          <p><strong>Service:</strong> ${escapeHtml(service || 'Non spécifié')}</p>
          <hr>
          <p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>
        `,
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error('Resend error:', err);
      return new Response(
        JSON.stringify({ error: 'Failed to send' }),
        { status: 500, headers }
      );
    }

    return new Response(
      JSON.stringify({ success: true }),
      { status: 200, headers }
    );
  } catch (e) {
    console.error('Contact error:', e);
    return new Response(
      JSON.stringify({ error: 'Server error' }),
      { status: 500, headers }
    );
  }
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
