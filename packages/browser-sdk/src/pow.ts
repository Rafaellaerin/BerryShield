export async function solvePow(
  seed: string,
  difficultyBits: number,
  maxNonce = 20_000_000,
  deadlineMs = 12_000,
): Promise<number> {
  if (!crypto?.subtle) throw new Error("WebCrypto is required for proof-of-work");
  if (difficultyBits < 4 || difficultyBits > 24) throw new Error("invalid difficulty");

  const encoder = new TextEncoder();
  const deadline = performance.now() + deadlineMs;
  for (let nonce = 0; nonce <= maxNonce; nonce++) {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(`${seed}:${nonce}`)),
    );
    if (leadingZeroBits(digest) >= difficultyBits) return nonce;
    if ((nonce & 0xff) === 0) {
      if (performance.now() > deadline) throw new Error("proof-of-work timeout");
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  }
  throw new Error("proof-of-work exhausted");
}

export function leadingZeroBits(bytes: Uint8Array): number {
  let count = 0;
  for (const value of bytes) {
    if (value === 0) {
      count += 8;
      continue;
    }
    for (let bit = 7; bit >= 0; bit--) {
      if ((value & (1 << bit)) === 0) count++;
      else return count;
    }
  }
  return count;
}
