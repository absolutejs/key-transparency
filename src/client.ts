import { KeyTransparencyError } from "./errors";
import { defineKeyTransparencyProviderManifest } from "./provider";
import type {
  KeyTransparencyClient,
  KeyTransparencyEvidence,
  KeyTransparencyLabel,
  KeyTransparencyMonitorResult,
  KeyTransparencyProvider,
  KeyTransparencySearchResult,
  KeyTransparencyStoredView,
  KeyTransparencyUpdateResult,
  KeyTransparencyVerifiedView,
  KeyTransparencyViewStore,
} from "./types";

const DEFAULT_MAX_EVIDENCE_AGE_MS = 5 * 60_000;
const DEFAULT_CLOCK_SKEW_MS = 60_000;

const encodeBase64Url = (value: Uint8Array): string =>
  globalThis
    .btoa(Array.from(value, (byte) => String.fromCharCode(byte)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

const digest = async (domain: string, value: Uint8Array): Promise<string> => {
  const domainBytes = new TextEncoder().encode(`${domain}\0`);
  const bytes = new Uint8Array(domainBytes.length + value.length);
  bytes.set(domainBytes);
  bytes.set(value, domainBytes.length);
  return `sha256:${encodeBase64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
  )}`;
};

export const keyTransparencyLabelDigest = (
  label: KeyTransparencyLabel,
): Promise<string> =>
  digest("org.absolutejs.key-transparency.label.v1", label.bytes);

export const keyTransparencyValueDigest = (
  value: Uint8Array,
): Promise<string> => digest("org.absolutejs.key-transparency.value.v1", value);

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length &&
  left.every((byte, index) => byte === right[index]);

const validSafeInteger = (value: number): boolean =>
  Number.isSafeInteger(value) && value >= 0;

const cloneView = (
  view: KeyTransparencyVerifiedView,
): KeyTransparencyVerifiedView => ({
  fullTreeHead: view.fullTreeHead.slice(),
  head: {
    ...view.head,
    rootHash: view.head.rootHash.slice(),
    signedTreeHead: view.head.signedTreeHead.slice(),
  },
});

const assertView = (
  current: KeyTransparencyVerifiedView,
  prior: KeyTransparencyVerifiedView | undefined,
  expectedLogId: string,
): void => {
  const head = current.head;
  if (
    head.logId !== expectedLogId ||
    !validSafeInteger(head.treeSize) ||
    head.treeSize === 0 ||
    !validSafeInteger(head.timestamp) ||
    head.rootHash.length === 0 ||
    head.signedTreeHead.length === 0 ||
    current.fullTreeHead.length === 0
  ) {
    throw new KeyTransparencyError(
      "evidence-invalid",
      "Provider returned an invalid verified tree view.",
    );
  }
  if (prior === undefined) return;
  if (
    head.logId !== prior.head.logId ||
    head.treeSize < prior.head.treeSize ||
    head.timestamp < prior.head.timestamp ||
    (head.treeSize === prior.head.treeSize &&
      !equalBytes(head.rootHash, prior.head.rootHash))
  ) {
    throw new KeyTransparencyError(
      "fork-detected",
      "The verified tree view rolled back or conflicted with local state.",
    );
  }
};

const assertEvidence = (input: {
  readonly evidence: KeyTransparencyEvidence;
  readonly expectedOperation: KeyTransparencyEvidence["operation"];
  readonly expectedSubjectDigests: readonly string[];
  readonly now: number;
  readonly providerId: string;
  readonly protocolRevision: string;
  readonly requireIndependentAuditor: boolean;
  readonly view: KeyTransparencyVerifiedView;
  readonly maxClockSkewMs: number;
  readonly maxEvidenceAgeMs: number;
}): void => {
  const { evidence, view } = input;
  if (
    evidence.providerId !== input.providerId ||
    evidence.protocolRevision !== input.protocolRevision ||
    evidence.operation !== input.expectedOperation ||
    evidence.treeHeadHash !== encodeBase64Url(view.head.rootHash) ||
    evidence.subjectDigests.length !== input.expectedSubjectDigests.length ||
    evidence.subjectDigests.some(
      (value, index) => value !== input.expectedSubjectDigests[index],
    ) ||
    !validSafeInteger(evidence.verifiedAt) ||
    evidence.verifiedAt > input.now + input.maxClockSkewMs ||
    evidence.verifiedAt < input.now - input.maxEvidenceAgeMs
  ) {
    throw new KeyTransparencyError(
      "evidence-invalid",
      "Provider verification evidence was not bound to this operation.",
    );
  }
  const auditorIds = new Set<string>();
  for (const receipt of evidence.auditorReceipts) {
    if (
      receipt.auditorId.trim() === "" ||
      auditorIds.has(receipt.auditorId) ||
      receipt.signature.length === 0 ||
      receipt.treeHeadHash !== evidence.treeHeadHash ||
      !validSafeInteger(receipt.verifiedAt) ||
      receipt.verifiedAt > input.now + input.maxClockSkewMs ||
      receipt.verifiedAt < input.now - input.maxEvidenceAgeMs
    ) {
      throw new KeyTransparencyError(
        "evidence-invalid",
        "Auditor evidence was not independently bound to this tree head.",
      );
    }
    auditorIds.add(receipt.auditorId);
  }
  if (input.requireIndependentAuditor && auditorIds.size === 0) {
    throw new KeyTransparencyError(
      "evidence-invalid",
      "The provider claimed an independent auditor but returned no auditor evidence.",
    );
  }
};

export const createMemoryKeyTransparencyViewStore =
  (): KeyTransparencyViewStore => {
    const states = new Map<string, KeyTransparencyStoredView>();
    return {
      load: async (logId) => {
        const state = states.get(logId);
        return state === undefined
          ? undefined
          : { revision: state.revision, view: cloneView(state.view) };
      },
      save: async ({ expectedRevision, state }) => {
        const current = states.get(state.view.head.logId);
        if (current?.revision !== expectedRevision) return false;
        states.set(state.view.head.logId, {
          revision: state.revision,
          view: cloneView(state.view),
        });
        return true;
      },
    };
  };

export const createKeyTransparencyClient = (options: {
  readonly clockSkewMs?: number;
  readonly maxEvidenceAgeMs?: number;
  readonly now?: () => number;
  readonly provider: KeyTransparencyProvider;
  readonly store: KeyTransparencyViewStore;
}): KeyTransparencyClient => {
  const manifest = defineKeyTransparencyProviderManifest(
    options.provider.manifest,
  );
  const now = options.now ?? Date.now;
  const maxClockSkewMs = options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  const maxEvidenceAgeMs =
    options.maxEvidenceAgeMs ?? DEFAULT_MAX_EVIDENCE_AGE_MS;
  if (
    !validSafeInteger(maxClockSkewMs) ||
    !validSafeInteger(maxEvidenceAgeMs)
  ) {
    throw new KeyTransparencyError(
      "configuration",
      "Evidence age and clock skew must be non-negative safe integers.",
    );
  }

  const load = async (logId: string) => options.store.load(logId);
  const persist = async (
    result: { readonly view: KeyTransparencyVerifiedView },
    prior: KeyTransparencyStoredView | undefined,
  ) => {
    assertView(result.view, prior?.view, manifest.logId);
    const saved = await options.store.save({
      expectedRevision: prior?.revision,
      state: {
        revision: (prior?.revision ?? -1) + 1,
        view: result.view,
      },
    });
    if (!saved) {
      throw new KeyTransparencyError(
        "state-conflict",
        "Verified tree state changed concurrently; retry from the latest view.",
      );
    }
  };

  const priorFor = async (): Promise<KeyTransparencyStoredView | undefined> =>
    load(manifest.logId);

  const monitor = async (
    mode: "contact" | "owner",
    labels: readonly KeyTransparencyLabel[],
  ): Promise<KeyTransparencyMonitorResult> => {
    if (labels.length === 0) {
      throw new KeyTransparencyError(
        "configuration",
        "At least one opaque label is required for monitoring.",
      );
    }
    const prior = await priorFor();
    const subjectDigests = await Promise.all(
      labels.map(keyTransparencyLabelDigest),
    );
    const result = await options.provider.monitor({
      labels,
      mode,
      priorView: prior?.view,
    });
    assertEvidence({
      evidence: result.evidence,
      expectedOperation:
        mode === "contact" ? "contact-monitor" : "owner-monitor",
      expectedSubjectDigests: subjectDigests,
      maxClockSkewMs,
      maxEvidenceAgeMs,
      now: now(),
      providerId: manifest.id,
      protocolRevision: manifest.protocolRevision,
      requireIndependentAuditor: manifest.security.independentlyOperatedAuditor,
      view: result.view,
    });
    if (result.status === "fork-detected") {
      throw new KeyTransparencyError(
        "fork-detected",
        "The provider detected inconsistent transparency-log views.",
      );
    }
    await persist(result, prior);
    return result;
  };

  return {
    monitorContacts: ({ labels }) => monitor("contact", labels),
    monitorOwner: ({ labels }) => monitor("owner", labels),
    search: async ({ label }): Promise<KeyTransparencySearchResult> => {
      const prior = await priorFor();
      const subjectDigest = await keyTransparencyLabelDigest(label);
      const result = await options.provider.search({
        label,
        priorView: prior?.view,
      });
      assertEvidence({
        evidence: result.evidence,
        expectedOperation: "search",
        expectedSubjectDigests: [subjectDigest],
        maxClockSkewMs,
        maxEvidenceAgeMs,
        now: now(),
        providerId: manifest.id,
        protocolRevision: manifest.protocolRevision,
        requireIndependentAuditor:
          manifest.security.independentlyOperatedAuditor,
        view: result.view,
      });
      if ((result.value === undefined) !== (result.version === undefined)) {
        throw new KeyTransparencyError(
          "evidence-invalid",
          "Search value and version must either both be present or both be absent.",
        );
      }
      await persist(result, prior);
      return result;
    },
    update: async ({
      authorization,
      label,
      value,
    }): Promise<KeyTransparencyUpdateResult> => {
      if (authorization.length === 0 || value.length === 0) {
        throw new KeyTransparencyError(
          "configuration",
          "Update authorization and value must not be empty.",
        );
      }
      const prior = await priorFor();
      const subjectDigest = await keyTransparencyLabelDigest(label);
      const expectedValueDigest = await keyTransparencyValueDigest(value);
      const result = await options.provider.update({
        authorization,
        label,
        priorView: prior?.view,
        value,
      });
      assertEvidence({
        evidence: result.evidence,
        expectedOperation: "update",
        expectedSubjectDigests: [subjectDigest],
        maxClockSkewMs,
        maxEvidenceAgeMs,
        now: now(),
        providerId: manifest.id,
        protocolRevision: manifest.protocolRevision,
        requireIndependentAuditor:
          manifest.security.independentlyOperatedAuditor,
        view: result.view,
      });
      if (
        result.valueDigest !== expectedValueDigest ||
        !validSafeInteger(result.version)
      ) {
        throw new KeyTransparencyError(
          "evidence-invalid",
          "Update evidence was not bound to the submitted value.",
        );
      }
      await persist(result, prior);
      return result;
    },
  };
};
