const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept',
};

const AUTH_URL = 'https://auth.fu.do/api';

export default {
  async fetch(request, env, ctx) {

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Guardar credenciales: POST /save-creds
    if (path === '/save-creds' && request.method === 'POST') {
      const body = await request.json();
      if (!body.apiKey || !body.apiSecret) {
        return jsonRes({ error: 'apiKey y apiSecret requeridos' }, 400);
      }
      await env.FUDO_SECRETS.put('apiKey', body.apiKey);
      await env.FUDO_SECRETS.put('apiSecret', body.apiSecret);
      const token = await getOrRefresh(env);
      return jsonRes({ ok: true, token: token.token, exp: token.exp });
    }

    // Obtener token vigente: GET /token
    if (path === '/token' && request.method === 'GET') {
      const token = await getOrRefresh(env);
      return jsonRes(token);
    }

    // Proxy hacia FUDO
    const target = url.searchParams.get('target');
    if (target) {
      const allowed = ['auth.fu.do', 'api.fu.do'];
      const targetUrl = new URL(target);
      if (!allowed.some(d => targetUrl.hostname === d)) {
        return jsonRes({ error: 'Dominio no permitido' }, 403);
      }
      const newReq = new Request(target, {
        method: request.method,
        headers: request.headers,
        body: request.method !== 'GET' ? request.body : undefined,
      });
      const res = await fetch(newReq);
      const body = await res.text();
      return new Response(body, {
        status: res.status,
        headers: {
          ...CORS,
          'Content-Type': res.headers.get('Content-Type') || 'application/json',
        },
      });
    }

    return jsonRes({ error: 'Endpoint no encontrado' }, 404);
  },
};

async function getOrRefresh(env) {
  const stored = await env.FUDO_SECRETS.get('token_data');
  if (stored) {
    const data = JSON.parse(stored);
    const now = Math.floor(Date.now() / 1000);
    if (data.exp && (data.exp - now) > 300) {
      return data;
    }
  }
  return await refreshToken(env);
}

async function refreshToken(env) {
  const apiKey = await env.FUDO_SECRETS.get('apiKey');
  const apiSecret = await env.FUDO_SECRETS.get('apiSecret');
  if (!apiKey || !apiSecret) {
    throw new Error('Sin credenciales guardadas en el Worker.');
  }
  const res = await fetch(AUTH_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ apiKey, apiSecret }),
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error('Error auth ' + res.status + ': ' + txt);
  }
  const data = await res.json();
  await env.FUDO_SECRETS.put('token_data', JSON.stringify(data));
  return data;
}

function jsonRes(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
