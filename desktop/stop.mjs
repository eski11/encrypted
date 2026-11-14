import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
try {
  const root = dirname(fileURLToPath(import.meta.url));
  const token = readFileSync(join(root, 'state', 'owner-token'), 'utf8').trim();
  const response = await fetch('http://127.0.0.1:9752/shutdown', { method: 'POST', headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(3000) });
  if (!response.ok) throw new Error();
  console.log('ENCPTD server stopped. Close the internet connector window separately if it is open.');
} catch { console.log('ENCPTD was not running, or this folder does not have its owner token.'); }
