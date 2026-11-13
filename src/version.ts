import pkg from "../package.json" with { type: "json" };

/**
 * Single source of truth for the release version: package.json. The compiled
 * binary inlines this at build time, so `sns --version` always matches the
 * package it was built from.
 */
export const VERSION: string = pkg.version;
