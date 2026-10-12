// api/protection.js

// Detectar específicamente curl_cffi
// curl_cffi deja huellas en los headers TLS/HTTP2
const hasCurlSignature = 
  // curl_cffi a veces no envía todos los headers de un browser real
  (!request.headers.get('sec-ch-ua') && userAgent.includes('Mozilla')) ||
  // Orden de headers sospechoso
  (acceptEncoding.includes('br') && !acceptEncoding.includes('gzip'));

if (hasCurlSignature) {
  console.warn('🚫 curl_cffi DETECTADO');
  return new Response('Blocked', { status: 403 });
}

export const config = {
  runtime: 'edge',
};

export default async function handler(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // === DETECCIÓN DE HERRAMIENTAS DE FUZZING ===
  const userAgent = request.headers.get('user-agent') || '';
  const acceptEncoding = request.headers.get('accept-encoding') || '';
  const acceptLanguage = request.headers.get('accept-language') || '';
  const secFetchDest = request.headers.get('sec-fetch-dest') || '';
  const secFetchMode = request.headers.get('sec-fetch-mode') || '';
  
  // curl_cffi y herramientas similares dejan huellas específicas
  const suspiciousIndicators = [
    // curl_cffi a veces no envía headers de navegador completo
    !secFetchDest && !secFetchMode,
    // Accept-Language vacío o muy genérico
    acceptLanguage === '' || acceptLanguage === '*',
    // Patrones de User-Agent sospechosos (aunque esté rotado)
    userAgent.includes('curl') || userAgent.includes('python'),
  ];

  // Si 2 o más indicadores son verdaderos, es muy probable que sea un bot
  const suspiciousScore = suspiciousIndicators.filter(Boolean).length;
  
  if (suspiciousScore >= 2) {
    console.warn(`🎯 FUZZING DETECTADO (Score: ${suspiciousScore}/3)`);
    console.warn(`  - UA: ${userAgent.substring(0, 50)}...`);
    console.warn(`  - IP: ${request.headers.get('x-real-ip') || 'unknown'}`);
    
    // Devolver un 403 definitivo
    return new Response(
      JSON.stringify({ 
        error: 'Forbidden',
        message: 'Automated access detected',
        timestamp: new Date().toISOString()
      }),
      { 
        status: 403,
        headers: { 
          'Content-Type': 'application/json',
          'X-Block-Reason': 'Bot detection',
          'Cache-Control': 'no-store'
        }
      }
    );
  }

  // === BLOQUEO DE ARCHIVOS SENSIBLES ===
  const sensitivePatterns = [
    /\.env$/i,
    /\.git/i,
    /\.sql$/i,
    /\.bak$/i,
    /\.log$/i,
    /config\.json$/i,
    /settings\.json$/i,
    /backup\./i,
  ];

  for (const pattern of sensitivePatterns) {
    if (pattern.test(pathname)) {
      console.warn(` ARCHIVO SENSIBLE BLOQUEADO: ${pathname}`);
      return new Response(
        JSON.stringify({ error: 'Forbidden', file: pathname }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }

  // === SERVICIO DE ARCHIVOS PERMITIDOS ===
  // Si es un archivo estático permitido (HTML, imágenes, etc.)
  const allowedExtensions = /\.(html?|png|jpg|jpeg|gif|svg|css|js|ico)$/i;
  
  if (pathname === '/' || allowedExtensions.test(pathname)) {
    try {
      const originalUrl = new URL(request.url);
      originalUrl.pathname = pathname;
      
      const response = await fetch(originalUrl.toString(), {
        method: request.method,
        headers: request.headers,
        redirect: 'manual'
      });

      const newResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      });

      newResponse.headers.set('X-Protected', 'true');
      return newResponse;
      
    } catch (error) {
      console.error('Error:', error);
      return new Response('Internal Error', { status: 500 });
    }
  }

  // === DEFAULT: BLOQUEAR TODO LO DEMÁS ===
  return new Response(
    JSON.stringify({ error: 'Not Found' }),
    { 
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    }
  );
}