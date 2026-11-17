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

/**
 * Reads a line without echoing it. Uses raw mode on a TTY so characters are handled
 * directly and never printed. Piped input (non-TTY) is read as-is, for automation.
 */
let piped: AsyncIterator<string> | undefined;

/** Shared line reader for non-TTY input, so successive prompts each get their own line. */
async function readPipedLine(): Promise<string> {
  if (!piped) {
    const rl = createInterface({ input: stdin });
    piped = rl[Symbol.asyncIterator]() as AsyncIterator<string>;
  }
  const next = await piped.next();
  return next.done ? "" : next.value;
}

async function readHidden(prompt: string): Promise<string> {
  stdout.write(prompt);
  if (!stdin.isTTY) {
    const line = await readPipedLine();
    stdout.write("\n");
    return line;
  }
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (chunk: Buffer) => {
      for (const ch of chunk.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          cleanup();
          stdout.write("\n");
          resolve(buf);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          reject(new Error("Cancelled."));
          return;
        }
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set");
  stdout.write("Admin email: ");
  const rawEmail = stdin.isTTY
    ? await (async () => {
        const rl = createInterface({ input: stdin, output: stdout });
        const v = await rl.question("");
        rl.close();
        return v;
      })()
    : await readPipedLine();

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
