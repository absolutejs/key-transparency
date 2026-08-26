# `@absolutejs/key-transparency`

Provider-neutral key-transparency contracts, local rollback protection,
provider selection, and conformance tools for AbsoluteJS.

This is an early `0.x` foundation. It does not implement the IETF KEYTRANS
cryptography and it does not turn an ordinary key directory into a transparency
log. Providers must verify the protocol's proofs and signatures before returning
results through these contracts.

## Why this is separate from E2EE

MLS protects conversation content, but its Authentication Service binds identities
to device signature keys. A compromised or malicious Authentication Service can
issue a valid credential for a ghost device. Key transparency makes those key
bindings append-only, searchable, monitorable, and capable of exposing inconsistent
views.

Keeping `@absolutejs/key-transparency` separate from `@absolutejs/e2ee` prevents
the encryption provider or identity authority from silently acting as its own
independent verifier.

## Provider boundary

Providers live in `key-transparency-providers` and follow the package pattern
`@absolutejs/key-transparency-<provider>`. A provider owns draft-specific proof
parsing and cryptographic verification. This package additionally enforces:

- an exact protocol revision rather than a floating “KEYTRANS compatible” claim;
- operation, label, value, provider, and tree-head binding for evidence;
- monotonically increasing locally persisted tree views;
- compare-and-set persistence so concurrent clients cannot overwrite newer views;
- explicit contact monitoring, owner monitoring, auditor, privacy, and assurance
  capabilities;
- independent audit evidence before an `audited` claim is accepted.

Applications pass opaque, application-derived label bytes. Raw email addresses,
phone numbers, usernames, and other enumerable identifiers should not cross this
boundary.

```ts
import {
  createKeyTransparencyClient,
  createMemoryKeyTransparencyViewStore,
  selectKeyTransparencyProvider,
} from "@absolutejs/key-transparency";

const provider = selectKeyTransparencyProvider(providers, {
  minimumAssurance: "reviewed",
  protocolRevision: "draft-ietf-keytrans-protocol-05",
  requireContactMonitoring: true,
  requireOwnerMonitoring: true,
  requireSplitViewDetection: true,
  roles: ["client", "monitor"],
  runtime: "browser",
});

const client = createKeyTransparencyClient({
  provider,
  store: createMemoryKeyTransparencyViewStore(),
});
```

The memory view store is for tests and short-lived demos. Production clients need
durable, rollback-resistant storage.

## Version-bound certification

Provider manifests are claims; certification reports are evidence tied to one
exact provider version, protocol revision, runtime, completion time, scenario
set, and evidence digest. Production admission should require fresh conformance
and adversarial claims. Official vectors, cross-implementation behavior, and an
independent audit are separate claims and cannot be declared without their
corresponding evidence.

## Standards status

The package currently pins
`draft-ietf-keytrans-protocol-05` and
`draft-ietf-keytrans-architecture-09`. Internet-Drafts are works in progress and
can change. Providers must publish a new `0.x` version when changing protocol
revision; the selector never silently treats revisions as equivalent.

- Protocol: <https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/>
- Architecture: <https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/>
- MLS architecture: <https://www.rfc-editor.org/rfc/rfc9750>

Public TypeScript contracts use type aliases rather than interfaces.

## License

Apache-2.0
