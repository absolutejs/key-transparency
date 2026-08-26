import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "detect unauthorized messaging keys",
      "select a key transparency provider",
      "monitor transparency log consistency",
    ],
    keywords: [
      "key transparency",
      "e2ee",
      "MLS",
      "ghost device",
      "split view",
      "auditor",
    ],
    protocols: ["IETF KEYTRANS"],
  },
  identity: {
    accent: "#7c3aed",
    category: "security",
    description:
      "Provider-neutral key transparency contracts, local rollback protection, deterministic provider selection, and conformance tools.",
    docsUrl: "https://github.com/absolutejs/key-transparency",
    name: "@absolutejs/key-transparency",
    tagline: "Make unauthorized messaging keys visible and verifiable.",
  },
  settings: Type.Object({}, { additionalProperties: false }),
  wiring: [],
});
