// api/protection.js

export const config = {
  runtime: 'edge', // Esto lo convierte en Edge Function
};

// Configuración
const CHALLENGE_COOKIE_NAME = 'x-bot-verification';
const CHALLENGE_COOKIE_VALUE = 'passed';

// Patrones sospechosos (fuzzing/scanning)
const SUSPICIOUS_PATTERNS = [
  /\.env$/i,
  /\.git/i,
  /\.sql$/i,
  /\.bak$/i,
  /\.log$/i,
  /\.txt$/i,
  /\.json$/i,
  /\/\./,
  /wp-admin/i,
  /phpmyadmin/i
];

export default async function handler(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // 1. IGNORAR ARCHIVOS ESTÁTICOS INOCUOS
  if (
    pathname.startsWith('/_next/') ||
    pathname === '/favicon.ico' ||
    /\.(png|jpg|jpeg|gif|svg|css|woff2|js)$/i.test(pathname)
  ) {
    return serveOriginalFile(request, pathname);
  }

  // 2. DETECCIÓN DE PATRONES (Bloqueo inmediato)
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(pathname)) {
      console.warn(`🚫 BLOQUEADO: ${pathname} desde ${request.headers.get('x-real-ip') || 'unknown'}`);
      return new Response(
        JSON.stringify({ error: 'Forbidden', reason: 'Suspicious path pattern' }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }

  // 3. VERIFICAR COOKIE DE DESAFÍO
  const cookies = parseCookies(request.headers.get('cookie') || '');
  const hasValidCookie = cookies[CHALLENGE_COOKIE_NAME] === CHALLENGE_COOKIE_VALUE;

  if (!hasValidCookie) {
    console.log(`️ JS Challenge enviado para: ${pathname}`);
    
    // Devolver HTML con JavaScript Challenge
    const challengeHtml = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verificando...</title>
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
          }
          .container { text-align: center; }
          .loader { 
            border: 4px solid rgba(255,255,255,0.3); 
            border-top: 4px solid white; 
            border-radius: 50%; 
            width: 50px; 
            height: 50px; 
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
          }
          @keyframes spin { 
            0% { transform: rotate(0deg); } 
            100% { transform: rotate(360deg); } 
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="loader"></div>
          <h2>Verificando que eres humano...</h2>
          <p>Por favor espera un momento</p>
        </div>
        <script>
          // Establecer cookie de verificación
          document.cookie = "${CHALLENGE_COOKIE_NAME}=${CHALLENGE_COOKIE_VALUE}; path=/; max-age=3600; SameSite=Lax";
          
          // Recargar después de 500ms
          setTimeout(() => {
            window.location.reload();
          }, 500);
        </script>
      </body>
      </html>
    `;

    return new Response(challengeHtml, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Frame-Options': 'DENY'
      }
    });
  }

  // 4. SI TIENE LA COOKIE: Servir el archivo original
  console.log(`✅ Verificado: ${pathname}`);
  return serveOriginalFile(request, pathname);
}

// Función para servir el archivo original
async function serveOriginalFile(request, pathname) {
  try {
    // Construir la URL original del archivo
    const originalUrl = new URL(request.url);
    originalUrl.pathname = pathname;
    
    // Hacer fetch al archivo estático
    const response = await fetch(originalUrl.toString(), {
      method: request.method,
      headers: request.headers,
      redirect: 'manual'
    });

    // Clonar la respuesta y agregar headers de seguridad
    const newResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });

    newResponse.headers.set('X-Bot-Challenge', 'PASSED');
    newResponse.headers.set('X-Content-Type-Options', 'nosniff');

    return newResponse;
  } catch (error) {
    console.error('Error sirviendo archivo:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
}

// Helper para parsear cookies
function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;
  
  cookieString.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  
  return cookies;
}