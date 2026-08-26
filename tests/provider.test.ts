import { describe, expect, test } from "bun:test";
import {
  KEY_TRANSPARENCY_PROTOCOL_REVISION,
  KeyTransparencyError,
  KeyTransparencyProviderSelectionError,
  defineKeyTransparencyProviderManifest,
  explainKeyTransparencyProviderCompatibility,
  selectKeyTransparencyProvider,
} from "../src";
import { createFixtureProvider, fixtureManifest } from "./fixture";

const requirements = {
  minimumAssurance: "reviewed" as const,
  protocolRevision: KEY_TRANSPARENCY_PROTOCOL_REVISION,
  requireContactMonitoring: true,
  requireOwnerMonitoring: true,
  requirePrivateLookups: true,
  requireSplitViewDetection: true,
  roles: ["client", "monitor"] as const,
  runtime: "browser" as const,
};

describe("provider manifests", () => {
  test("validates and freezes explicit security claims", () => {
    const manifest = defineKeyTransparencyProviderManifest(fixtureManifest());
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(manifest.roles)).toBe(true);
    expect(Object.isFrozen(manifest.security)).toBe(true);
  });

  test("requires audit evidence for audited assurance", () => {
    expect(() =>
      defineKeyTransparencyProviderManifest({
        ...fixtureManifest(),
        security: {
          ...fixtureManifest().security,
          assurance: "audited",
        },
      }),
    ).toThrow("independent audit evidence");
  });

  test("does not let a colocated monitor imply an independent auditor", () => {
    expect(() =>
      defineKeyTransparencyProviderManifest({
        ...fixtureManifest(),
        security: {
          ...fixtureManifest().security,
          independentlyOperatedAuditor: true,
          thirdPartyAuditing: false,
        },
      }),
    ).toThrow(KeyTransparencyError);
  });
});

describe("provider selection", () => {
  test("requires the exact Internet-Draft revision", () => {
    const result = explainKeyTransparencyProviderCompatibility(
      fixtureManifest(),
      { ...requirements, protocolRevision: "draft-ietf-keytrans-protocol-04" },
    );
    expect(result.compatible).toBe(false);
    expect(result.reasons[0]).toContain(
      "is not draft-ietf-keytrans-protocol-04",
    );
  });

  test("fails closed with capability reasons", () => {
    const provider = createFixtureProvider();
    expect(() =>
      selectKeyTransparencyProvider([provider], {
        ...requirements,
        requireIndependentAuditor: true,
      }),
    ).toThrow(KeyTransparencyProviderSelectionError);
    expect(
      explainKeyTransparencyProviderCompatibility(provider.manifest, {
        ...requirements,
        requireIndependentAuditor: true,
      }).reasons,
    ).toContain(
      "an independently operated auditor is required but unavailable",
    );
  });
});
