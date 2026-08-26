import { expect, test } from "bun:test";
import { checkKeyTransparencyProviderConformance } from "../src";
import { createFixtureProvider, fixtureNow } from "./fixture";

test("runs provider-neutral key transparency conformance", async () => {
  const result = await checkKeyTransparencyProviderConformance({
    createProvider: createFixtureProvider,
    fixtureLabel: new Uint8Array([1, 2, 3]),
    now: () => fixtureNow,
  });
  expect(result).toEqual({ issues: [], passed: true });
});
