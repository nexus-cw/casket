export function encode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decode(s: string): Buffer {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  const padded2 = pad === 2 ? padded + '==' : pad === 3 ? padded + '=' : padded;
  return Buffer.from(padded2, 'base64');
}
