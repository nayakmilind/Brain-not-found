import { Link } from "react-router-dom";

export function ShieldMark() {
  return (
    <svg viewBox="0 0 32 36" role="img" aria-label="Shield">
      <path
        d="M16 2.5 28 7v9.2c0 8.1-5.3 14.4-12 17.3C9.3 30.6 4 24.3 4 16.2V7l12-4.5Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
      />
      <path
        d="m11.5 17 3 3 6.5-7"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
      />
    </svg>
  );
}

export function Brand({ href = "/login" }: { href?: string }) {
  return (
    <Link className="brand-link" to={href} aria-label="Privacy Shield home">
      <span className="brand-mark" aria-hidden="true">
        <ShieldMark />
      </span>
      <span className="brand-copy">
        <strong>Privacy Shield</strong>
        <span>AI</span>
      </span>
    </Link>
  );
}
