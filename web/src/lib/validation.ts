import { z } from "zod";

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email()
  .max(254);

export const credentialsSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(256),
});

export const signupSchema = z.object({
  email: emailSchema,
  password: z.string().min(12).max(256),
});

export const fileNameSchema = z
  .string()
  .trim()
  .min(1)
  .max(255)
  // Reject path separators and control characters: names are labels, never paths.
  .refine((s) => !/[\\/\u0000-\u001f]/.test(s) && s !== "." && s !== "..", "invalid file name");

export const uuidSchema = z.string().uuid();
