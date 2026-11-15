import { z } from "zod";

const booleanFromEnv = z
  .enum(["true", "false"])
  .transform((value) => value === "true")
  .catch(false);

const envSchema = z.object({
  VITE_API_BASE_URL: z
    .string()
    .trim()
    .min(1)
    .refine(
      (value) => value.startsWith("/") || URL.canParse(value),
      "VITE_API_BASE_URL must be a path or absolute URL",
    )
    .default("/"),
  VITE_ENABLE_MONITORING: booleanFromEnv,
  VITE_ENABLE_ASSISTANT: booleanFromEnv,
});

export const env = envSchema.parse(import.meta.env);
