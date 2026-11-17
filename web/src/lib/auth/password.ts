import argon2 from "argon2";

// OWASP-recommended Argon2id parameters (memory 19 MiB, 2 iterations, 1 lane).
const OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export function validatePasswordPolicy(password: string): string | null {
  if (password.length < 12) return "Password must be at least 12 characters.";
  if (password.length > 256) return "Password must be at most 256 characters.";
  return null;
}
