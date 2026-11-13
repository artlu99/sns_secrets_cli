import sodium from "libsodium-wrappers-sumo";

let pending: Promise<void> | null = null;

export function sodiumReady(): Promise<void> {
  pending ??= sodium.ready;
  return pending;
}

export function getSodium(): typeof sodium {
  return sodium;
}
