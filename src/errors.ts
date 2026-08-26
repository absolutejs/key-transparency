export class KeyTransparencyError extends Error {
  readonly code:
    "configuration" | "evidence-invalid" | "fork-detected" | "state-conflict";

  constructor(code: KeyTransparencyError["code"], message: string) {
    super(message);
    this.name = "KeyTransparencyError";
    this.code = code;
  }
}

export class KeyTransparencyProviderSelectionError extends Error {
  readonly rejected: Readonly<Record<string, readonly string[]>>;

  constructor(rejected: Readonly<Record<string, readonly string[]>>) {
    super("No key-transparency provider satisfies the requested policy.");
    this.name = "KeyTransparencyProviderSelectionError";
    this.rejected = rejected;
  }
}
