import { writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
writeFileSync(
  join(root, 'dist', 'cjs', 'package.json'),
  JSON.stringify({ type: 'commonjs' }, null, 2) + '\n',
);
