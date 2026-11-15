import { z } from "zod";

export const credentialsSchema = z.object({
  email: z.email("Enter a valid email address."),
  password: z
    .string()
    .min(12, "Use at least 12 characters.")
    .max(128, "Password must be 128 characters or fewer."),
});

export type CredentialsForm = z.infer<typeof credentialsSchema>;
