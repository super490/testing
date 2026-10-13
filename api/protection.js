// api/protection.js
export const config = {
  runtime: 'edge',
};

const CHALLENGE_COOKIE = 'x-verified';
const CHALLENGE_VALUE = '1';

export default async function handler(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // === 1. IGNORAR ARCHIVOS ESENCIALES DEL FRAMEWORK ===
  if (
    pathname.startsWith('/_next/') ||
    pathname === '/favicon.ico' ||
    pathname === '/vercel.svg'
  ) {
    return serveFile(pathname);
  }

  // === 2. BLOQUEO INMEDIATO DE ARCHIVOS SENSIBLES ===
  // Sin importar si tiene cookie o no, estos archivos NUNCA se sirven
  const sensitiveFiles = [
    /\.env$/i,
    /\.git/i,
    /\.sql$/i,
    /\.bak$/i,
    /\.log$/i,
    /\.txt$/i,
    /\.json$/i,
    /config/i,
    /settings/i,
    /backup/i,
    /password/i,
    /dump/i,
  ];

  for (const pattern of sensitiveFiles) {
    if (pattern.test(pathname)) {
      console.warn(`🚫 BLOQUEO DIRECTO: ${pathname}`);
      return new Response(
        JSON.stringify({ error: 'Forbidden', path: pathname }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }

  // === 3. VERIFICAR COOKIE DE AUTENTICACIÓN ===
  const cookies = parseCookies(request.headers.get('cookie') || '');
  const hasValidCookie = cookies[CHALLENGE_COOKIE] === CHALLENGE_VALUE;

  if (hasValidCookie) {
    // Cookie válida - servir archivo solicitado
    console.log(`✅ Cookie válida: ${pathname}`);
    return serveFile(pathname);
  }

  // === 4. JS CHALLENGE (curl_cffi NO puede ejecutar esto) ===
  console.log(` JS Challenge para: ${pathname}`);
  
  const challengeHtml = `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verificando...</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      color: white;
    }
    .container { text-align: center; padding: 2rem; }
    .spinner {
      width: 60px;
      height: 60px;
      border: 4px solid rgba(255,255,255,0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto 1.5rem;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    p { opacity: 0.9; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="spinner"></div>
    <h1>Verificando navegador...</h1>
    <p>Por favor espera un momento</p>
  </div>
  <script>
    (function() {
      // Establecer cookie de verificación
      document.cookie = "${CHALLENGE_COOKIE}=${CHALLENGE_VALUE}; path=/; max-age=3600; SameSite=Lax";
      
      // Recargar la página después de 300ms
      setTimeout(function() {
        window.location.reload();
      }, 300);
    })();
  </script>
</body>
</html>`;

  return new Response(challengeHtml, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'X-Challenge': 'required'
    }
  });
}

// Función para servir archivos estáticos
async function serveFile(pathname) {
  try {
    const url = new URL(`https://example.com${pathname}`);
    const response = await fetch(url.toString());
    
    if (response.status === 404) {
      return new Response(
        JSON.stringify({ error: 'Not Found' }),
        { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    const newResponse = new Response(response.body, {
      status: response.status,
      headers: response.headers
    });

    newResponse.headers.set('X-Served-By', 'edge-function');
    return newResponse;
    
  } catch (error) {
    console.error('Error:', error);
    return new Response('Internal Error', { status: 500 });
  }
}

// Helper para parsear cookies
function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;
  
  cookieString.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[decodeURIComponent(name)] = decodeURIComponent(value);
    }
  });
  
  return cookies;
}