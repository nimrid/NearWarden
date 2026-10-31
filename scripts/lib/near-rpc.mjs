/**
 * Minimal NEAR JSON-RPC client using only Node builtins.
 * Honours http(s)_proxy via an HTTP CONNECT tunnel so it works in
 * sandboxed environments where direct DNS for Node is unavailable.
 */
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

function connectViaProxy(proxyUrl, host, port) {
  return new Promise((resolve, reject) => {
    const proxy = new URL(proxyUrl);
    const req = http.request({
      host: proxy.hostname,
      port: Number(proxy.port),
      method: 'CONNECT',
      path: `${host}:${port}`,
    });
    req.on('connect', (_res, socket) => {
      const tlsSocket = tls.connect({ socket, servername: host }, () => resolve(tlsSocket));
      tlsSocket.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

export async function rpc(url, method, params) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 'ag', method, params });
  const target = new URL(url);
  const proxyUrl = process.env.https_proxy || process.env.HTTPS_PROXY || process.env.http_proxy;

  const responseBody = await new Promise(async (resolve, reject) => {
    if (proxyUrl && target.protocol === 'https:') {
      try {
        const tlsSocket = await connectViaProxy(proxyUrl, target.hostname, 443);
        const request =
          `POST ${target.pathname} HTTP/1.1\r\n` +
          `Host: ${target.hostname}\r\n` +
          `Content-Type: application/json\r\n` +
          `Content-Length: ${Buffer.byteLength(body)}\r\n` +
          `Connection: close\r\n\r\n` +
          body;
        let raw = Buffer.alloc(0);
        tlsSocket.on('data', (c) => (raw = Buffer.concat([raw, c])));
        tlsSocket.on('end', () => {
          const sep = raw.indexOf('\r\n\r\n');
          const head = raw.subarray(0, sep).toString();
          let payload = raw.subarray(sep + 4);
          if (/transfer-encoding:\s*chunked/i.test(head)) {
            const parts = [];
            let rest = payload;
            while (true) {
              const lineEnd = rest.indexOf('\r\n');
              const size = parseInt(rest.subarray(0, lineEnd).toString(), 16);
              if (!size) break;
              parts.push(rest.subarray(lineEnd + 2, lineEnd + 2 + size));
              rest = rest.subarray(lineEnd + 2 + size + 2);
            }
            payload = Buffer.concat(parts);
          }
          resolve(payload.toString());
        });
        tlsSocket.on('error', reject);
        tlsSocket.write(request);
      } catch (e) {
        reject(e);
      }
      return;
    }
    const req = https.request(
      {
        hostname: target.hostname,
        path: target.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.end(body);
  });

  const json = JSON.parse(responseBody);
  if (json.error) {
    throw new Error(`RPC ${method} failed: ${JSON.stringify(json.error)}`);
  }
  return json.result;
}

export async function viewFunction(rpcUrl, accountId, methodName, args = {}) {
  const result = await rpc(rpcUrl, 'query', {
    request_type: 'call_function',
    account_id: accountId,
    method_name: methodName,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
    finality: 'optimistic',
  });
  return JSON.parse(Buffer.from(result.result).toString());
}
