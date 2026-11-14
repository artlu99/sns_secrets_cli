import type { SVGProps } from "react";

/**
 * Inline stroke icons (16-grid, currentColor) — no icon font, no remote
 * assets: MV3 CSP allows only same-origin, and bundled SVG survives it.
 */

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function svgProps({ size, ...rest }: IconProps): SVGProps<SVGSVGElement> {
  return {
    width: size ?? 16,
    height: size ?? 16,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.5,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
    ...rest,
  };
}

export function KeyIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <circle cx="5.75" cy="8" r="2.9" />
      <path d="M8.65 8h5.1M11.45 8v2.4M13.75 8v1.7" />
    </svg>
  );
}

export function EyeIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M1.7 8C3.2 4.9 5.6 3.3 8 3.3s4.8 1.6 6.3 4.7C12.8 11.1 10.4 12.7 8 12.7S3.2 11.1 1.7 8Z" />
      <circle cx="8" cy="8" r="1.9" />
    </svg>
  );
}

export function EyeOffIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M3.1 5.2C2.6 5.9 2.1 6.8 1.7 8c1.5 3.1 3.9 4.7 6.3 4.7 1.2 0 2.4-.4 3.5-1.1M6.2 3.8C6.8 3.5 7.4 3.3 8 3.3c2.4 0 4.8 1.6 6.3 4.7-.6 1.2-1.3 2.2-2.1 3" />
      <path d="M2 2l12 12" />
    </svg>
  );
}

export function CopyIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <rect x="5.75" y="5.75" width="7.5" height="7.5" rx="1.5" />
      <path d="M10.25 3.5h-5.5a1.25 1.25 0 0 0-1.25 1.25v5.5" />
    </svg>
  );
}

export function CheckIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M3 8.6 6.4 12 13 4.6" />
    </svg>
  );
}

export function LockIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <rect x="3.25" y="7" width="9.5" height="6.25" rx="1.5" />
      <path d="M5.4 7V5.4a2.6 2.6 0 0 1 5.2 0V7" />
    </svg>
  );
}

export function SyncIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M13.5 8a5.5 5.5 0 1 1-1.7-3.97M13.5 2.6v2.9h-2.9" />
    </svg>
  );
}

export function TagIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M2.4 8.5V3.4a1 1 0 0 1 1-1h5.1a1 1 0 0 1 .72.3l4.8 4.85a1 1 0 0 1 0 1.4l-4.5 4.5a1 1 0 0 1-1.42 0L2.7 9.2a1 1 0 0 1-.3-.7Z" />
      <circle cx="5.7" cy="5.7" r=".85" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function SearchIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <circle cx="7.1" cy="7.1" r="4.6" />
      <path d="M10.4 10.4 13.6 13.6" />
    </svg>
  );
}

export function NotesIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M2.4 4h11.2M2.4 8h11.2M2.4 12h7.2" />
    </svg>
  );
}

export function FolderIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M2 12.4V4.1a1 1 0 0 1 1-1h3.1l1.7 1.9h5.2a1 1 0 0 1 1 1v6.4a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1Z" />
    </svg>
  );
}

export function LayoutIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <rect x="2.25" y="2.25" width="5" height="5" rx="1.2" />
      <rect x="8.75" y="2.25" width="5" height="5" rx="1.2" />
      <rect x="2.25" y="8.75" width="5" height="5" rx="1.2" />
      <rect x="8.75" y="8.75" width="5" height="5" rx="1.2" />
    </svg>
  );
}

export function EmptyVaultIcon(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <rect x="2.6" y="3.4" width="10.8" height="9.2" rx="1.8" />
      <circle cx="8" cy="8" r="2.1" />
      <path d="M8 10.1v1.6" />
    </svg>
  );
}
