/**
 * Interactive first-admin creation. Run once on a fresh install:
 *   DATABASE_URL=... npm run create-admin
 * The password is read with echo disabled and never logged.
 */
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { eq } from "drizzle-orm";
import { getDb } from "../src/db/client";
import { users } from "../src/db/schema";
import { hashPassword } from "../src/lib/auth/password";
import { emailSchema } from "../src/lib/validation";

/** Reads a line without echoing it: output is muted while the answer is typed. */
async function readHidden(prompt: string): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout, terminal: true });
  let muted = false;
  const write = (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput.bind(rl);
  (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = (s: string) => {
    if (!muted) write(s);
  };
  stdout.write(prompt);
  muted = true;
  const answer = await rl.question("");
  muted = false;
  stdout.write("\n");
  rl.close();
  return answer;
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set");
  const rl = createInterface({ input: stdin, output: stdout });
  const rawEmail = await rl.question("Admin email: ");
  rl.close();

  const emailParsed = emailSchema.safeParse(rawEmail);
  if (!emailParsed.success) throw new Error("Invalid email address.");
  const email = emailParsed.data;

  const password = await readHidden("Admin password (min 12 chars): ");
  const confirm = await readHidden("Confirm password: ");
  if (password !== confirm) throw new Error("Passwords do not match.");
  if (password.length < 12 || password.length > 256) throw new Error("Password must be 12-256 characters.");

  const db = getDb();
  const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
  if (existing) throw new Error("A user with that email already exists.");

  const passwordHash = await hashPassword(password);
  await db.insert(users).values({
    email,
    passwordHash,
    role: "admin",
    emailVerifiedAt: new Date(),
  });
  console.log(`Admin created: ${email}`);
  console.log("Sign in, then enrol TOTP before doing anything else (mandatory for admins).");
  process.exit(0);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
