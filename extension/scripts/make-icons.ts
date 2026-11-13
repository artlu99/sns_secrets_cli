/**
 * Regenerates public/icons/*.png from the SVG source below. Run once (and
 * after design changes): `bun scripts/make-icons.ts`. The PNGs are committed;
 * sharp is a devDependency purely for this script.
 *
 * The mark: a key silhouette on the dashboard's dark background — bold
 * strokes only, so it stays legible at 16 px.
 */
import { mkdirSync } from "node:fs";
import sharp from "sharp";

const svg = `
<svg width="512" height="512" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" rx="110" fill="#0f1115"/>
  <rect x="16" y="16" width="480" height="480" rx="96" fill="none" stroke="#262c37" stroke-width="12"/>
  <g fill="none" stroke="#4d8dfd" stroke-width="44" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="188" cy="256" r="84"/>
    <path d="M 272 256 L 408 256"/>
    <path d="M 348 256 L 348 320"/>
    <path d="M 408 256 L 408 308"/>
  </g>
</svg>`;

mkdirSync("public/icons", { recursive: true });
for (const size of [16, 32, 48, 128]) {
  await sharp(Buffer.from(svg))
    .resize(size, size)
    .png()
    .toFile(`public/icons/${size}.png`);
  console.log(`public/icons/${size}.png`);
}
