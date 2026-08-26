export const KEY_TRANSPARENCY_PROVIDER_CONTRACT = 1 as const;
export const KEY_TRANSPARENCY_PROTOCOL_REVISION =
  "draft-ietf-keytrans-protocol-05" as const;
export const KEY_TRANSPARENCY_ARCHITECTURE_REVISION =
  "draft-ietf-keytrans-architecture-09" as const;

export type KeyTransparencyAssurance = "audited" | "experimental" | "reviewed";

export type KeyTransparencyCostModel = "byo" | "free" | "paid-paas";

export type KeyTransparencyRuntime =
  "browser" | "bun" | "capacitor-android" | "capacitor-ios" | "node";

export type KeyTransparencyRole = "auditor" | "client" | "log" | "monitor";

export type KeyTransparencyProviderSecurity = {
  readonly assurance: KeyTransparencyAssurance;
  readonly auditUrls?: readonly string[];
  readonly contactMonitoring: boolean;
  readonly independentlyOperatedAuditor: boolean;
  readonly ownerMonitoring: boolean;
  readonly privateLookups: boolean;
  readonly splitViewDetection: boolean;
  readonly thirdPartyAuditing: boolean;
};

export type KeyTransparencyProviderManifest = {
  readonly contract: typeof KEY_TRANSPARENCY_PROVIDER_CONTRACT;
  readonly costModel: KeyTransparencyCostModel;
  readonly description: string;
  readonly id: string;
  readonly logId: string;
  readonly packageName: `@absolutejs/key-transparency-${string}`;
  readonly protocolRevision: string;
  readonly roles: readonly KeyTransparencyRole[];
  readonly runtimes: readonly KeyTransparencyRuntime[];
  readonly security: KeyTransparencyProviderSecurity;
  readonly version: string;
};

export type KeyTransparencyProviderRequirements = {
  readonly minimumAssurance?: KeyTransparencyAssurance;
  readonly pinnedProviderId?: string;
  readonly protocolRevision: string;
  readonly requireContactMonitoring?: boolean;
  readonly requireIndependentAuditor?: boolean;
  readonly requireOwnerMonitoring?: boolean;
  readonly requirePrivateLookups?: boolean;
  readonly requireSplitViewDetection?: boolean;
  readonly requireThirdPartyAuditing?: boolean;
  readonly roles: readonly KeyTransparencyRole[];
  readonly runtime: KeyTransparencyRuntime;
};

export type KeyTransparencyProviderCompatibility = {
  readonly compatible: boolean;
  readonly reasons: readonly string[];
};

export type KeyTransparencyLabel = {
  /** Opaque, application-derived label bytes. Do not pass a raw email address. */
  readonly bytes: Uint8Array;
};

export type KeyTransparencyTreeHead = {
  readonly logId: string;
  readonly rootHash: Uint8Array;
  readonly signedTreeHead: Uint8Array;
  readonly timestamp: number;
  readonly treeSize: number;
};

export type KeyTransparencyVerifiedView = {
  readonly fullTreeHead: Uint8Array;
  readonly head: KeyTransparencyTreeHead;
};

export type KeyTransparencyStoredView = {
  readonly revision: number;
  readonly view: KeyTransparencyVerifiedView;
};

export type KeyTransparencyEvidenceOperation =
  "contact-monitor" | "owner-monitor" | "search" | "update";

export type KeyTransparencyAuditorReceipt = {
  readonly auditorId: string;
  readonly signature: Uint8Array;
  readonly treeHeadHash: string;
  readonly verifiedAt: number;
};

export type KeyTransparencyEvidence = {
  readonly auditorReceipts: readonly KeyTransparencyAuditorReceipt[];
  readonly operation: KeyTransparencyEvidenceOperation;
  readonly protocolRevision: string;
  readonly providerId: string;
  readonly subjectDigests: readonly string[];
  readonly treeHeadHash: string;
  readonly verifiedAt: number;
};

export type KeyTransparencySearchResult = {
  readonly evidence: KeyTransparencyEvidence;
  readonly value?: Uint8Array;
  readonly version?: number;
  readonly view: KeyTransparencyVerifiedView;
};

export type KeyTransparencyUpdateResult = {
  readonly evidence: KeyTransparencyEvidence;
  readonly valueDigest: string;
  readonly version: number;
  readonly view: KeyTransparencyVerifiedView;
};

export type KeyTransparencyMonitoredChange = {
  readonly currentValueDigest?: string;
  readonly labelDigest: string;
  readonly previousValueDigest?: string;
  readonly version: number;
};

export type KeyTransparencyMonitorResult = {
  readonly changes: readonly KeyTransparencyMonitoredChange[];
  readonly evidence: KeyTransparencyEvidence;
  readonly status: "consistent" | "fork-detected";
  readonly view: KeyTransparencyVerifiedView;
};

export type KeyTransparencyProvider = {
  readonly manifest: KeyTransparencyProviderManifest;
  readonly monitor: (input: {
    readonly labels: readonly KeyTransparencyLabel[];
    readonly mode: "contact" | "owner";
    readonly priorView?: KeyTransparencyVerifiedView;
  }) => Promise<KeyTransparencyMonitorResult>;
  readonly search: (input: {
    readonly label: KeyTransparencyLabel;
    readonly priorView?: KeyTransparencyVerifiedView;
  }) => Promise<KeyTransparencySearchResult>;
  readonly update: (input: {
    readonly authorization: Uint8Array;
    readonly label: KeyTransparencyLabel;
    readonly priorView?: KeyTransparencyVerifiedView;
    readonly value: Uint8Array;
  }) => Promise<KeyTransparencyUpdateResult>;
};

export type KeyTransparencyViewStore = {
  readonly load: (
    logId: string,
  ) => Promise<KeyTransparencyStoredView | undefined>;
  readonly save: (input: {
    readonly expectedRevision?: number;
    readonly state: KeyTransparencyStoredView;
  }) => Promise<boolean>;
};

export type KeyTransparencyClient = {
  readonly monitorContacts: (input: {
    readonly labels: readonly KeyTransparencyLabel[];
  }) => Promise<KeyTransparencyMonitorResult>;
  readonly monitorOwner: (input: {
    readonly labels: readonly KeyTransparencyLabel[];
  }) => Promise<KeyTransparencyMonitorResult>;
  readonly search: (input: {
    readonly label: KeyTransparencyLabel;
  }) => Promise<KeyTransparencySearchResult>;
  readonly update: (input: {
    readonly authorization: Uint8Array;
    readonly label: KeyTransparencyLabel;
    readonly value: Uint8Array;
  }) => Promise<KeyTransparencyUpdateResult>;
};
