# Security

Report vulnerabilities privately through GitHub Security Advisories on the
`absolutejs/key-transparency` repository.

## Trust boundaries

- Providers own protocol encoding, proof verification, tree-head signatures,
  commitments, VRFs, monitoring proofs, and auditor signatures.
- The core package checks that verified results are bound to the exact operation,
  opaque labels, submitted value, provider, protocol revision, and tree head.
- The application owns privacy-preserving label derivation, update authorization,
  durable local view storage, user-visible device changes, and incident response.
- An auditor is independent only when it is operated under a meaningfully separate
  trust and administrative domain from the log.

## Fail-closed rules

- Never send raw enumerable identity values as labels.
- Never accept a provider result without cryptographic proof verification.
- Never overwrite a newer local tree view or accept a smaller tree.
- Treat equal-size tree heads with different roots as a fork.
- Treat provider, protocol, operation, label, value, or tree-head mismatches as
  invalid evidence.
- Do not describe the IETF drafts as finalized RFCs.
- Do not claim independent auditing merely because the log signs its own head.

Local rollback protection does not by itself detect a split view shown to two
clients with disjoint histories. Contact monitoring, owner monitoring, gossip or
distinguished-head walking, and genuinely independent auditors remain necessary.
