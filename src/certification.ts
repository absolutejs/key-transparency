import { KeyTransparencyError } from "./errors";
import type {
  KeyTransparencyProviderManifest,
  KeyTransparencyRuntime,
} from "./types";

export const KEY_TRANSPARENCY_CERTIFICATION_CONTRACT = 1 as const;
export const KEY_TRANSPARENCY_CERTIFICATION_SUITE =
  "absolutejs-key-transparency-certification/1" as const;

export type KeyTransparencyCertificationClaim =
  | "adversarial-lifecycle"
  | "cross-implementation"
  | "independent-audit"
  | "official-vectors"
  | "provider-conformance"
  | "runtime-browser"
  | "runtime-bun"
  | "runtime-node"
  | "split-view-drill";

export type KeyTransparencyCertificationImplementation = {
  readonly name: string;
  readonly version: string;
};

export type KeyTransparencyCertificationVectorEvidence = {
  readonly digestSha256: string;
  readonly sourceUrl: string;
};

export type KeyTransparencyCertificationAuditEvidence = {
  readonly digestSha256: string;
  readonly reportUrl: string;
};

export type KeyTransparencyCertificationReport = {
  readonly audits: readonly KeyTransparencyCertificationAuditEvidence[];
  readonly claims: readonly KeyTransparencyCertificationClaim[];
  readonly completedAt: string;
  readonly contract: typeof KEY_TRANSPARENCY_CERTIFICATION_CONTRACT;
  readonly evidenceDigestSha256: string;
  readonly implementations: readonly KeyTransparencyCertificationImplementation[];
  readonly protocolRevision: string;
  readonly provider: {
    readonly id: string;
    readonly packageName: KeyTransparencyProviderManifest["packageName"];
    readonly version: string;
  };
  readonly runtime: KeyTransparencyRuntime;
  readonly scenarios: readonly string[];
  readonly suite: typeof KEY_TRANSPARENCY_CERTIFICATION_SUITE;
  readonly vectors: readonly KeyTransparencyCertificationVectorEvidence[];
};

export type KeyTransparencyCertificationPolicy = {
  readonly manifest: KeyTransparencyProviderManifest;
  readonly maximumAgeMs: number;
  readonly now?: Date;
  readonly requiredClaims: readonly KeyTransparencyCertificationClaim[];
  readonly runtime: KeyTransparencyRuntime;
};

export type KeyTransparencyCertificationResult = {
  readonly issues: readonly string[];
  readonly passed: boolean;
  readonly report: KeyTransparencyCertificationReport;
};

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const HTTPS_URL_PATTERN = /^https:\/\//;
const MAXIMUM_CLOCK_SKEW_MS = 300_000;
const nonEmpty = (value: string): boolean => value.trim().length > 0;
const unique = (values: readonly string[]): boolean =>
  new Set(values).size === values.length;

const freezeReport = (
  report: KeyTransparencyCertificationReport,
): KeyTransparencyCertificationReport =>
  Object.freeze({
    ...report,
    audits: Object.freeze(
      report.audits.map((value) => Object.freeze({ ...value })),
    ),
    claims: Object.freeze([...report.claims]),
    implementations: Object.freeze(
      report.implementations.map((value) => Object.freeze({ ...value })),
    ),
    provider: Object.freeze({ ...report.provider }),
    scenarios: Object.freeze([...report.scenarios]),
    vectors: Object.freeze(
      report.vectors.map((value) => Object.freeze({ ...value })),
    ),
  });

export const defineKeyTransparencyCertificationReport = (
  report: KeyTransparencyCertificationReport,
): KeyTransparencyCertificationReport => {
  if (report.contract !== KEY_TRANSPARENCY_CERTIFICATION_CONTRACT) {
    throw new KeyTransparencyError(
      "configuration",
      `Unsupported key-transparency certification contract ${String(report.contract)}.`,
    );
  }
  if (report.suite !== KEY_TRANSPARENCY_CERTIFICATION_SUITE) {
    throw new KeyTransparencyError(
      "configuration",
      "Unsupported key-transparency certification suite.",
    );
  }
  if (
    !nonEmpty(report.provider.id) ||
    !nonEmpty(report.provider.version) ||
    !nonEmpty(report.protocolRevision) ||
    !SHA256_PATTERN.test(report.evidenceDigestSha256) ||
    !Number.isFinite(Date.parse(report.completedAt))
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Certification identity, protocol, completion time, or evidence digest is invalid.",
    );
  }
  if (
    report.claims.length === 0 ||
    !unique(report.claims) ||
    report.scenarios.length === 0 ||
    !unique(report.scenarios)
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Certification claims and scenarios must be non-empty and unique.",
    );
  }
  if (
    report.implementations.some(
      ({ name, version }) => !nonEmpty(name) || !nonEmpty(version),
    ) ||
    !unique(
      report.implementations.map(({ name, version }) => `${name}@${version}`),
    )
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Certification implementation identities must be complete and unique.",
    );
  }
  if (
    report.vectors.some(
      ({ digestSha256, sourceUrl }) =>
        !SHA256_PATTERN.test(digestSha256) ||
        !HTTPS_URL_PATTERN.test(sourceUrl),
    ) ||
    report.audits.some(
      ({ digestSha256, reportUrl }) =>
        !SHA256_PATTERN.test(digestSha256) ||
        !HTTPS_URL_PATTERN.test(reportUrl),
    )
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Certification vectors and audits require HTTPS sources and SHA-256 digests.",
    );
  }
  if (
    report.claims.includes("official-vectors") &&
    report.vectors.length === 0
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Official-vector certification requires vector evidence.",
    );
  }
  if (
    report.claims.includes("independent-audit") &&
    report.audits.length === 0
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Independent-audit certification requires audit evidence.",
    );
  }
  if (
    report.claims.includes("cross-implementation") &&
    new Set(report.implementations.map(({ name }) => name)).size < 2
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Cross-implementation certification requires two distinct implementations.",
    );
  }
  return freezeReport(report);
};

export const checkKeyTransparencyCertification = (
  report: KeyTransparencyCertificationReport,
  policy: KeyTransparencyCertificationPolicy,
): KeyTransparencyCertificationResult => {
  const defined = defineKeyTransparencyCertificationReport(report);
  const issues: string[] = [];
  const now = policy.now ?? new Date();
  const completedAt = new Date(defined.completedAt);
  if (!Number.isSafeInteger(policy.maximumAgeMs) || policy.maximumAgeMs < 1) {
    throw new KeyTransparencyError(
      "configuration",
      "Certification maximum age must be a positive safe integer.",
    );
  }
  if (
    defined.provider.id !== policy.manifest.id ||
    defined.provider.packageName !== policy.manifest.packageName ||
    defined.provider.version !== policy.manifest.version
  ) {
    issues.push("certification is bound to another provider release");
  }
  if (defined.protocolRevision !== policy.manifest.protocolRevision) {
    issues.push("certification is bound to another protocol revision");
  }
  if (defined.runtime !== policy.runtime) {
    issues.push(`certification runtime is not ${policy.runtime}`);
  }
  if (completedAt.getTime() - now.getTime() > MAXIMUM_CLOCK_SKEW_MS) {
    issues.push("certification completion time is in the future");
  }
  if (now.getTime() - completedAt.getTime() > policy.maximumAgeMs) {
    issues.push("certification is stale");
  }
  for (const claim of policy.requiredClaims) {
    if (!defined.claims.includes(claim)) {
      issues.push(`certification claim ${claim} is missing`);
    }
  }
  return Object.freeze({
    issues: Object.freeze(issues),
    passed: issues.length === 0,
    report: defined,
  });
};
