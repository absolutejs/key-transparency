import {
  KEY_TRANSPARENCY_PROTOCOL_REVISION,
  createMemoryKeyTransparencyViewStore,
  keyTransparencyLabelDigest,
  keyTransparencyValueDigest,
  type KeyTransparencyEvidence,
  type KeyTransparencyEvidenceOperation,
  type KeyTransparencyProvider,
  type KeyTransparencyProviderManifest,
  type KeyTransparencyVerifiedView,
  type KeyTransparencyViewStore,
} from "../src";

export const fixtureNow = 1_800_000_000_000;

const base64Url = (value: Uint8Array): string =>
  Buffer.from(value).toString("base64url");

export const fixtureManifest = (
  id = "fixture",
): KeyTransparencyProviderManifest => ({
  contract: 1,
  costModel: "free",
  description: "Key transparency fixture provider",
  id,
  logId: "fixture-log",
  packageName: `@absolutejs/key-transparency-${id}`,
  protocolRevision: KEY_TRANSPARENCY_PROTOCOL_REVISION,
  roles: ["client", "monitor"],
  runtimes: ["browser", "bun"],
  security: {
    assurance: "reviewed",
    contactMonitoring: true,
    independentlyOperatedAuditor: false,
    ownerMonitoring: true,
    privateLookups: true,
    splitViewDetection: true,
    thirdPartyAuditing: false,
  },
  version: "0.1.0",
});

export const fixtureView = (
  treeSize: number,
  rootByte = treeSize,
): KeyTransparencyVerifiedView => ({
  fullTreeHead: new Uint8Array([0xa0, treeSize, rootByte]),
  head: {
    logId: "fixture-log",
    rootHash: new Uint8Array([rootByte]),
    signedTreeHead: new Uint8Array([0xb0, treeSize, rootByte]),
    timestamp: fixtureNow + treeSize,
    treeSize,
  },
});

const fixtureEvidence = (
  operation: KeyTransparencyEvidenceOperation,
  subjectDigests: readonly string[],
  view: KeyTransparencyVerifiedView,
): KeyTransparencyEvidence => ({
  auditorReceipts: [],
  operation,
  protocolRevision: KEY_TRANSPARENCY_PROTOCOL_REVISION,
  providerId: "fixture",
  subjectDigests,
  treeHeadHash: base64Url(view.head.rootHash),
  verifiedAt: fixtureNow,
});

export const createFixtureProvider = (
  options: {
    readonly alterEvidence?: (
      evidence: KeyTransparencyEvidence,
    ) => KeyTransparencyEvidence;
    readonly updateValueDigest?: string;
    readonly views?: readonly KeyTransparencyVerifiedView[];
  } = {},
): KeyTransparencyProvider => {
  let operation = 0;
  const nextView = () => {
    const configured = options.views?.[operation];
    operation += 1;
    return configured ?? fixtureView(operation);
  };
  const evidence = (
    kind: KeyTransparencyEvidenceOperation,
    digests: readonly string[],
    view: KeyTransparencyVerifiedView,
  ) => {
    const value = fixtureEvidence(kind, digests, view);
    return options.alterEvidence?.(value) ?? value;
  };
  return {
    manifest: fixtureManifest(),
    monitor: async ({ labels, mode }) => {
      const view = nextView();
      const digests = await Promise.all(labels.map(keyTransparencyLabelDigest));
      return {
        changes: [],
        evidence: evidence(
          mode === "contact" ? "contact-monitor" : "owner-monitor",
          digests,
          view,
        ),
        status: "consistent",
        view,
      };
    },
    search: async ({ label }) => {
      const view = nextView();
      return {
        evidence: evidence(
          "search",
          [await keyTransparencyLabelDigest(label)],
          view,
        ),
        value: new Uint8Array([7, 8, 9]),
        version: 1,
        view,
      };
    },
    update: async ({ label, value }) => {
      const view = nextView();
      return {
        evidence: evidence(
          "update",
          [await keyTransparencyLabelDigest(label)],
          view,
        ),
        valueDigest:
          options.updateValueDigest ??
          (await keyTransparencyValueDigest(value)),
        version: 1,
        view,
      };
    },
  };
};

export const createFixtureStore = (): KeyTransparencyViewStore =>
  createMemoryKeyTransparencyViewStore();
