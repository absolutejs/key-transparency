import { describe, expect, test } from "bun:test";
import {
  KEY_TRANSPARENCY_PROTOCOL_REVISION,
  checkKeyTransparencyCertification,
  defineKeyTransparencyCertificationReport,
  defineKeyTransparencyProviderManifest,
  type KeyTransparencyCertificationReport,
} from "../src";
import { fixtureManifest } from "./fixture";

const now = new Date("2026-08-26T20:00:00.000Z");
const manifest = defineKeyTransparencyProviderManifest({
  ...fixtureManifest(),
  protocolRevision: KEY_TRANSPARENCY_PROTOCOL_REVISION,
  version: "0.2.0",
});

const report = (
  overrides: Partial<KeyTransparencyCertificationReport> = {},
): KeyTransparencyCertificationReport => ({
  audits: [],
  claims: ["provider-conformance", "adversarial-lifecycle", "runtime-bun"],
  completedAt: now.toISOString(),
  contract: 1,
  evidenceDigestSha256: "a".repeat(64),
  implementations: [{ name: "fixture", version: "1.0.0" }],
  protocolRevision: manifest.protocolRevision,
  provider: {
    id: manifest.id,
    packageName: manifest.packageName,
    version: manifest.version,
  },
  runtime: "bun",
  scenarios: ["manifest", "rollback", "split-view"],
  suite: "absolutejs-key-transparency-certification/1",
  vectors: [],
  ...overrides,
});

describe("key-transparency provider certification", () => {
  test("accepts and freezes fresh exact-release evidence", () => {
    const result = checkKeyTransparencyCertification(report(), {
      manifest,
      maximumAgeMs: 86_400_000,
      now,
      requiredClaims: ["provider-conformance", "adversarial-lifecycle"],
      runtime: "bun",
    });
    expect(result.passed).toBe(true);
    expect(Object.isFrozen(result.report)).toBe(true);
    expect(Object.isFrozen(result.report.implementations)).toBe(true);
  });

  test("rejects release, protocol, runtime, freshness, and claim drift", () => {
    const result = checkKeyTransparencyCertification(
      report({
        claims: ["provider-conformance"],
        completedAt: "2026-08-20T20:00:00.000Z",
        protocolRevision: "another-protocol",
        provider: { ...report().provider, version: "0.1.0" },
        runtime: "browser",
      }),
      {
        manifest,
        maximumAgeMs: 86_400_000,
        now,
        requiredClaims: ["split-view-drill"],
        runtime: "bun",
      },
    );
    expect(result.issues).toEqual([
      "certification is bound to another provider release",
      "certification is bound to another protocol revision",
      "certification runtime is not bun",
      "certification is stale",
      "certification claim split-view-drill is missing",
    ]);
  });

  test("requires concrete evidence for high assurance claims", () => {
    expect(() =>
      defineKeyTransparencyCertificationReport(
        report({ claims: ["official-vectors"] }),
      ),
    ).toThrow("requires vector evidence");
    expect(() =>
      defineKeyTransparencyCertificationReport(
        report({ claims: ["independent-audit"] }),
      ),
    ).toThrow("requires audit evidence");
    expect(() =>
      defineKeyTransparencyCertificationReport(
        report({ claims: ["cross-implementation"] }),
      ),
    ).toThrow("requires two distinct implementations");
  });
});
