import { describe, expect, test } from "bun:test";
import {
  KeyTransparencyError,
  createKeyTransparencyClient,
  type KeyTransparencyViewStore,
} from "../src";
import {
  createFixtureProvider,
  createFixtureStore,
  fixtureNow,
  fixtureView,
} from "./fixture";

const label = { bytes: new TextEncoder().encode("opaque-label") };

const client = (
  provider = createFixtureProvider(),
  store = createFixtureStore(),
) =>
  createKeyTransparencyClient({
    now: () => fixtureNow,
    provider,
    store,
  });

describe("verified operations", () => {
  test("persists a verified search view and advances it through monitoring", async () => {
    const instance = client();
    await expect(instance.search({ label })).resolves.toMatchObject({
      version: 1,
    });
    await expect(
      instance.monitorContacts({ labels: [label] }),
    ).resolves.toMatchObject({ status: "consistent" });
    await expect(
      instance.monitorOwner({ labels: [label] }),
    ).resolves.toMatchObject({
      status: "consistent",
    });
  });

  test("rejects evidence copied from another label", async () => {
    const instance = client(
      createFixtureProvider({
        alterEvidence: (evidence) => ({
          ...evidence,
          subjectDigests: ["sha256:attacker-label"],
        }),
      }),
    );
    await expect(instance.search({ label })).rejects.toMatchObject({
      code: "evidence-invalid",
    });
  });

  test("rejects an auditor receipt copied from another tree head", async () => {
    const instance = client(
      createFixtureProvider({
        alterEvidence: (evidence) => ({
          ...evidence,
          auditorReceipts: [
            {
              auditorId: "independent-auditor",
              signature: new Uint8Array([1]),
              treeHeadHash: "different-tree-head",
              verifiedAt: fixtureNow,
            },
          ],
        }),
      }),
    );
    await expect(instance.search({ label })).rejects.toMatchObject({
      code: "evidence-invalid",
    });
  });

  test("rejects an update receipt copied from another value", async () => {
    const instance = client(
      createFixtureProvider({ updateValueDigest: "sha256:other-value" }),
    );
    await expect(
      instance.update({
        authorization: new Uint8Array([1]),
        label,
        value: new Uint8Array([2]),
      }),
    ).rejects.toMatchObject({ code: "evidence-invalid" });
  });
});

describe("local consistency", () => {
  test("rejects tree rollback", async () => {
    const instance = client(
      createFixtureProvider({ views: [fixtureView(2), fixtureView(1)] }),
    );
    await instance.search({ label });
    await expect(instance.search({ label })).rejects.toMatchObject({
      code: "fork-detected",
    });
  });

  test("rejects a conflicting root at the same tree size", async () => {
    const instance = client(
      createFixtureProvider({ views: [fixtureView(2, 2), fixtureView(2, 9)] }),
    );
    await instance.search({ label });
    await expect(instance.search({ label })).rejects.toBeInstanceOf(
      KeyTransparencyError,
    );
  });

  test("fails rather than overwriting concurrently changed state", async () => {
    const backing = createFixtureStore();
    let saves = 0;
    const conflicting: KeyTransparencyViewStore = {
      load: backing.load,
      save: async (input) => {
        saves += 1;
        return saves === 1 ? false : backing.save(input);
      },
    };
    await expect(
      client(createFixtureProvider(), conflicting).search({ label }),
    ).rejects.toMatchObject({
      code: "state-conflict",
    });
  });

  test("rejects stale verification evidence", async () => {
    const instance = createKeyTransparencyClient({
      maxEvidenceAgeMs: 1,
      now: () => fixtureNow + 2,
      provider: createFixtureProvider(),
      store: createFixtureStore(),
    });
    await expect(instance.search({ label })).rejects.toMatchObject({
      code: "evidence-invalid",
    });
  });
});
