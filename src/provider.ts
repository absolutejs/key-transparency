import {
  KeyTransparencyError,
  KeyTransparencyProviderSelectionError,
} from "./errors";
import {
  KEY_TRANSPARENCY_PROVIDER_CONTRACT,
  type KeyTransparencyAssurance,
  type KeyTransparencyProvider,
  type KeyTransparencyProviderCompatibility,
  type KeyTransparencyProviderManifest,
  type KeyTransparencyProviderRequirements,
} from "./types";

const assuranceRank: Readonly<Record<KeyTransparencyAssurance, number>> = {
  experimental: 0,
  reviewed: 1,
  audited: 2,
};

const packagePattern =
  /^@absolutejs\/key-transparency-[a-z0-9]+(?:-[a-z0-9]+)*$/;
const nonEmpty = (value: string): boolean => value.trim().length > 0;
const unique = <Value extends string>(values: readonly Value[]): boolean =>
  new Set(values).size === values.length;

export const defineKeyTransparencyProviderManifest = (
  manifest: KeyTransparencyProviderManifest,
): KeyTransparencyProviderManifest => {
  if (manifest.contract !== KEY_TRANSPARENCY_PROVIDER_CONTRACT) {
    throw new KeyTransparencyError(
      "configuration",
      `Unsupported key-transparency provider contract ${String(manifest.contract)}.`,
    );
  }
  if (
    !nonEmpty(manifest.id) ||
    !nonEmpty(manifest.logId) ||
    !packagePattern.test(manifest.packageName)
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Provider id, log id, and @absolutejs/key-transparency-<provider> package name are required.",
    );
  }
  if (
    !nonEmpty(manifest.description) ||
    !nonEmpty(manifest.protocolRevision) ||
    !nonEmpty(manifest.version)
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Provider description, protocol revision, and version are required.",
    );
  }
  if (
    manifest.roles.length === 0 ||
    !unique(manifest.roles) ||
    manifest.runtimes.length === 0 ||
    !unique(manifest.runtimes)
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Provider roles and runtimes must be non-empty and unique.",
    );
  }
  if (
    manifest.security.assurance === "audited" &&
    (manifest.security.auditUrls === undefined ||
      manifest.security.auditUrls.length === 0)
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "An audited provider must publish independent audit evidence.",
    );
  }
  if (
    manifest.security.independentlyOperatedAuditor &&
    !manifest.security.thirdPartyAuditing
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "An independent auditor claim requires third-party auditing support.",
    );
  }

  return Object.freeze({
    ...manifest,
    roles: Object.freeze([...manifest.roles]),
    runtimes: Object.freeze([...manifest.runtimes]),
    security: Object.freeze({
      ...manifest.security,
      auditUrls:
        manifest.security.auditUrls === undefined
          ? undefined
          : Object.freeze([...manifest.security.auditUrls]),
    }),
  });
};

export const explainKeyTransparencyProviderCompatibility = (
  manifest: KeyTransparencyProviderManifest,
  requirements: KeyTransparencyProviderRequirements,
): KeyTransparencyProviderCompatibility => {
  const reasons: string[] = [];
  if (
    requirements.pinnedProviderId !== undefined &&
    requirements.pinnedProviderId !== manifest.id
  ) {
    reasons.push(`provider id is not ${requirements.pinnedProviderId}`);
  }
  if (requirements.protocolRevision !== manifest.protocolRevision) {
    reasons.push(
      `protocol revision ${manifest.protocolRevision} is not ${requirements.protocolRevision}`,
    );
  }
  if (!manifest.runtimes.includes(requirements.runtime)) {
    reasons.push(`runtime ${requirements.runtime} is not supported`);
  }
  for (const role of requirements.roles) {
    if (!manifest.roles.includes(role)) reasons.push(`role ${role} is missing`);
  }
  if (
    requirements.minimumAssurance !== undefined &&
    assuranceRank[manifest.security.assurance] <
      assuranceRank[requirements.minimumAssurance]
  ) {
    reasons.push(
      `assurance ${manifest.security.assurance} is below ${requirements.minimumAssurance}`,
    );
  }
  const claims = [
    [
      requirements.requireContactMonitoring,
      manifest.security.contactMonitoring,
      "contact monitoring",
    ],
    [
      requirements.requireIndependentAuditor,
      manifest.security.independentlyOperatedAuditor,
      "an independently operated auditor",
    ],
    [
      requirements.requireOwnerMonitoring,
      manifest.security.ownerMonitoring,
      "owner monitoring",
    ],
    [
      requirements.requirePrivateLookups,
      manifest.security.privateLookups,
      "private lookups",
    ],
    [
      requirements.requireSplitViewDetection,
      manifest.security.splitViewDetection,
      "split-view detection",
    ],
    [
      requirements.requireThirdPartyAuditing,
      manifest.security.thirdPartyAuditing,
      "third-party auditing",
    ],
  ] as const;
  for (const [required, available, description] of claims) {
    if (required === true && !available)
      reasons.push(`${description} is required but unavailable`);
  }
  return Object.freeze({
    compatible: reasons.length === 0,
    reasons: Object.freeze(reasons),
  });
};

export const selectKeyTransparencyProvider = <
  Provider extends KeyTransparencyProvider,
>(
  providers: readonly Provider[],
  requirements: KeyTransparencyProviderRequirements,
): Provider => {
  const rejected: Record<string, readonly string[]> = {};
  const compatible = providers.filter((provider) => {
    const result = explainKeyTransparencyProviderCompatibility(
      provider.manifest,
      requirements,
    );
    if (!result.compatible) rejected[provider.manifest.id] = result.reasons;
    return result.compatible;
  });
  if (compatible.length === 0) {
    throw new KeyTransparencyProviderSelectionError(Object.freeze(rejected));
  }
  return compatible.toSorted((left, right) => {
    const difference =
      assuranceRank[right.manifest.security.assurance] -
      assuranceRank[left.manifest.security.assurance];
    return difference === 0
      ? left.manifest.id.localeCompare(right.manifest.id)
      : difference;
  })[0]!;
};
