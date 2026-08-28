import ShieldLogo from "./ShieldLogo";
import type { AppScreen } from "../types";

interface HeaderProps {
  screen: AppScreen;
  onNavigate: (screen: AppScreen) => void;
}

export default function Header({ screen, onNavigate }: HeaderProps) {
  const navItems: { label: string; screen: AppScreen }[] = [
    { label: "Scanner", screen: "home" },
    { label: "History", screen: "history" },
    { label: "Extension", screen: "extension" },
  ];

  return (
    <header className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-[var(--border)]">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
        <button
          onClick={() => onNavigate("home")}
          className="flex items-center gap-2.5 group"
        >
          <ShieldLogo size={28} />
          <span className="font-display font-700 text-[17px] text-[var(--foreground)] tracking-tight">
            Phish<span className="text-[var(--primary)]">Guard</span>
          </span>
        </button>

        <nav className="flex items-center gap-1">
          {navItems.map((item) => (
            <button
              key={item.screen}
              onClick={() => onNavigate(item.screen)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                screen === item.screen || (screen === "result" && item.screen === "home") || (screen === "analysis" && item.screen === "home") || (screen === "scanning" && item.screen === "home")
                  ? "bg-[var(--secondary)] text-[var(--primary)]"
                  : "text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--muted)]"
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
      </div>
    </header>
  );
}
