import argon2 from 'argon2';

export async function deriveKey(
  password: string,
  salt: Buffer,
  memoryCost: number,
  timeCost: number,
  parallelism: number,
  hashLength = 32,
): Promise<Buffer> {
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    memoryCost,
    timeCost,
    parallelism,
    hashLength,
    raw: true,
  });
  return hash as Buffer;
}
