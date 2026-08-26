import {
  createKeyTransparencyClient,
  createMemoryKeyTransparencyViewStore,
} from "./client";
import { defineKeyTransparencyProviderManifest } from "./provider";
import type { KeyTransparencyProvider } from "./types";

export type KeyTransparencyProviderConformanceResult = {
  readonly issues: readonly string[];
  readonly passed: boolean;
};

export const checkKeyTransparencyProviderConformance = async (options: {
  readonly createProvider: () =>
    KeyTransparencyProvider | Promise<KeyTransparencyProvider>;
  readonly fixtureLabel: Uint8Array;
  readonly now?: () => number;
}): Promise<KeyTransparencyProviderConformanceResult> => {
  const issues: string[] = [];
  let provider: KeyTransparencyProvider;
  try {
    provider = await options.createProvider();
    defineKeyTransparencyProviderManifest(provider.manifest);
  } catch (error) {
    return Object.freeze({
      issues: Object.freeze([
        error instanceof Error ? error.message : "provider creation failed",
      ]),
      passed: false,
    });
  }
  try {
    const client = createKeyTransparencyClient({
      now: options.now,
      provider,
      store: createMemoryKeyTransparencyViewStore(),
    });
    await client.search({ label: { bytes: options.fixtureLabel } });
  } catch (error) {
    issues.push(
      error instanceof Error ? error.message : "verified search failed",
    );
  }
  return Object.freeze({
    issues: Object.freeze(issues),
    passed: issues.length === 0,
  });
};
