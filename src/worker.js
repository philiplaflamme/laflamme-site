const ALLOWED_ORIGINS = [
  'https://dupuislaflamme.ca',
  'https://www.dupuislaflamme.ca',
  'https://laflamme-site.pages.dev',
];

const SECURITY_HEADERS = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_FIELD = 500;
const MAX_MESSAGE = 5000;

// Simple in-memory rate limit: max 3 submissions per IP per 10 minutes
const rateMap = new Map();
const RATE_WINDOW = 10 * 60 * 1000;
const RATE_MAX = 3;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW) {
    rateMap.set(ip, { start: now, count: 1 });
    return false;
  }
  entry.count++;
  if (entry.count > RATE_MAX) return true;
  return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Block access to config/dot files
    const blocked = ['/wrangler.jsonc', '/.gitignore', '/.git'];
    if (blocked.some(b => url.pathname.startsWith(b))) {
      return new Response('Not found', { status: 404 });
    }

    // Handle contact form POST
    if (url.pathname === '/api/contact' && request.method === 'POST') {
      return handleContact(request, env);
    }

    // Add security headers to static assets
    const response = await env.ASSETS.fetch(request);
    const newResponse = new Response(response.body, response);
    newResponse.headers.set('X-Content-Type-Options', 'nosniff');
    newResponse.headers.set('X-Frame-Options', 'DENY');
    newResponse.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    newResponse.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    return newResponse;
  }
};

async function handleContact(request, env) {
  // CSRF: validate Origin header
  const origin = request.headers.get('Origin') || '';
  if (!ALLOWED_ORIGINS.includes(origin)) {
    return respond(403, { error: 'Forbidden' });
  }

  // Rate limiting by IP
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) {
    return respond(429, { error: 'Too many requests' });
  }

  try {
    const data = await request.formData();

    // Honeypot: if the hidden "website" field is filled, it's a bot
    const honeypot = data.get('website') || '';
    if (honeypot) {
      // Silently accept to not tip off the bot
      return respond(200, { success: true });
    }

    const prenom = truncate(data.get('prenom') || '', MAX_FIELD);
    const nom = truncate(data.get('nom') || '', MAX_FIELD);
    const email = truncate(data.get('email') || '', MAX_FIELD);
    const service = truncate(data.get('service') || '', MAX_FIELD);
    const message = truncate(data.get('message') || '', MAX_MESSAGE);

    // Required fields
    if (!prenom || !email || !message) {
      return respond(400, { error: 'Missing required fields' });
    }

    // Email format validation
    if (!EMAIL_REGEX.test(email)) {
      return respond(400, { error: 'Invalid email' });
    }

    const fullName = nom ? `${prenom} ${nom}` : prenom;
    const safeSubject = `Nouveau message de ${escapeHtml(fullName)}`.slice(0, 200);

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
        subject: safeSubject,
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
      return respond(500, { error: 'Failed to send' });
    }

    return respond(200, { success: true });
  } catch (e) {
    return respond(500, { error: 'Server error' });
  }
}

function respond(status, body) {
  return new Response(JSON.stringify(body), { status, headers: SECURITY_HEADERS });
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) : str;
}
