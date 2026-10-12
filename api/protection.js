// api/protection.js
export const config = {
  runtime: 'edge',
};

export default async function handler(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // === DETECCIÓN DE curl_cffi Y HERRAMIENTAS DE FUZZING ===
  const userAgent = request.headers.get('user-agent') || '';
  const acceptEncoding = request.headers.get('accept-encoding') || '';
  const acceptLanguage = request.headers.get('accept-language') || '';
  const secFetchDest = request.headers.get('sec-fetch-dest') || '';
  const secFetchMode = request.headers.get('sec-fetch-mode') || '';
  const secChUa = request.headers.get('sec-ch-ua') || '';

  // Detectar específicamente curl_cffi
  const hasCurlSignature = 
    (!secChUa && userAgent.includes('Mozilla')) ||
    (!secFetchDest && !secFetchMode && pathname !== '/') ||
    (acceptLanguage === '' || acceptLanguage === '*');

  if (hasCurlSignature) {
    console.warn(' curl_cffi/FUZZING DETECTADO');
    console.warn(`  - UA: ${userAgent.substring(0, 100)}`);
    console.warn(`  - IP: ${request.headers.get('x-real-ip') || 'unknown'}`);
    
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
          'X-Block-Reason': 'Bot detection - curl_cffi signature',
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
    /\.txt$/i,
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
  const allowedExtensions = /\.(html?|png|jpg|jpeg|gif|svg|css|js|ico|woff2)$/i;
  
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
      console.error('Error sirviendo archivo:', error);
      return new Response('Internal Error', { status: 500 });
    }
  }

  // === DEFAULT: 404 ===
  return new Response(
    JSON.stringify({ error: 'Not Found' }),
    { 
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    }
  );
}