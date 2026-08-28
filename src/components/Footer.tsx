import ShieldLogo from "./ShieldLogo";

export default function Footer() {
  return (
    <footer className="border-t border-[var(--border)] mt-auto">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 py-6 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <ShieldLogo size={20} />
          <span className="font-display font-600 text-sm text-[var(--foreground)]">
            Phish<span className="text-[var(--primary)]">Guard</span>
          </span>
          <span className="text-[var(--border)] select-none">·</span>
          <span className="text-xs text-[var(--muted-foreground)]">URL threat detection</span>
        </div>
        <p className="text-xs text-[var(--muted-foreground)] text-center sm:text-right">
          Analysis is performed server-side. We never open or visit scanned URLs.
        </p>
      </div>
    </footer>
  );
}
