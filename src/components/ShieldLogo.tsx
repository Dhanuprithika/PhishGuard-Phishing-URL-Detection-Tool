interface ShieldLogoProps {
  size?: number;
  className?: string;
}

export default function ShieldLogo({ size = 32, className = "" }: ShieldLogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <path
        d="M16 2L4 7v9c0 7.18 5.16 13.9 12 15.93C22.84 29.9 28 23.18 28 16V7L16 2z"
        fill="url(#shield-gradient)"
      />
      <path
        d="M16 2L4 7v9c0 7.18 5.16 13.9 12 15.93C22.84 29.9 28 23.18 28 16V7L16 2z"
        stroke="url(#shield-stroke)"
        strokeWidth="1"
        fill="none"
        opacity="0.4"
      />
      <path
        d="M11 16.5l3.5 3.5 6.5-7"
        stroke="white"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <defs>
        <linearGradient id="shield-gradient" x1="4" y1="2" x2="28" y2="32" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#2563eb" />
          <stop offset="100%" stopColor="#1a56db" />
        </linearGradient>
        <linearGradient id="shield-stroke" x1="4" y1="2" x2="28" y2="32" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#93c5fd" />
          <stop offset="100%" stopColor="#3b82f6" />
        </linearGradient>
      </defs>
    </svg>
  );
}
