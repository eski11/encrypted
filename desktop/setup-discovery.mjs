// SPDX-License-Identifier: AGPL-3.0-only
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Discovery, saveJSON } from './discovery.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const directory = process.env.ENCPTD_DATA_DIR || join(root, 'state');
try {
  const discovery = new Discovery(directory);
  const config = await discovery.initialize();
  saveJSON(join(root, 'app-config.json'), config);
  if (process.argv[2]) saveJSON(resolve(process.argv[2]), config);
  await discovery.checkPublicFile();
  console.log('Automatic phone connection is configured. The signing key stays in this PC\'s server state.');
  console.log('Public app configuration saved in desktop/app-config.json. Include this file as iphone/Resources/Server.json when building your own app.');
} catch (error) { console.error(error.message); process.exitCode = 1; }
