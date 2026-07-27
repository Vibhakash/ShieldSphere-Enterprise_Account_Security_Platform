import { createFileRoute } from "@tanstack/react-router";
import { AuthPage } from "@/components/auth/AuthPage";
import { z } from "zod";

export const Route = createFileRoute("/auth")({
  validateSearch: z.object({
    mode: z.enum(["login", "register"]).optional(),
    redirect: z.string().optional(),
  }),
  component: AuthPage,
});
