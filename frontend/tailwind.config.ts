import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Sofia Sans",
          "SofiaSans",
          "Arial",
          "sans-serif",
        ],
      },
      colors: {
        // ── Mastercard design system ──────────────────────
        "canvas-cream": "#F3F0EE",
        "lifted-cream": "#FCFBFA",
        "ink-black": "#141413",
        "signal-orange": "#CF4500",
        "light-signal": "#F37338",
        "clay-brown": "#9A3A0A",
        "slate-gray": "#696969",
        "dust-taupe": "#D1CDC7",
        "link-blue": "#3860BE",
        "ghost-cream": "#E8E2DA",
        // ── Legacy primary (blue) — kept for chart colors ──
        primary: {
          50: "#eff6ff",
          100: "#dbeafe",
          200: "#bfdbfe",
          300: "#93c5fd",
          400: "#60a5fa",
          500: "#3b82f6",
          600: "#2563eb",
          700: "#1d4ed8",
          800: "#1e40af",
          900: "#1e3a8a",
          950: "#172554",
        },
        // ── Severity semantic colors ───────────────────────
        severity: {
          critical: "#dc2626",
          high: "#f97316",
          medium: "#eab308",
          low: "#22c55e",
        },
      },
      borderRadius: {
        btn: "20px",
        hero: "40px",
        pill: "999px",
      },
      boxShadow: {
        // Level 1 — floating nav pill
        "elev-1": "rgba(0, 0, 0, 0.04) 0px 4px 24px 0px",
        // Level 2 — hero frames, elevated cards
        "elev-2": "rgba(0, 0, 0, 0.08) 0px 24px 48px 0px",
        // Level 3 — dramatic feature tile (rare)
        "elev-3": "rgba(0, 0, 0, 0.25) 0px 70px 110px 0px",
      },
      letterSpacing: {
        // -2% on headlines (design system spec)
        display: "-0.02em",
        // -3% on nav/button labels
        tight: "-0.03em",
        // +4% on eyebrow labels
        eyebrow: "0.04em",
      },
      fontSize: {
        // Editorial scale
        "display-xl": ["64px", { lineHeight: "64px", letterSpacing: "-0.02em" }],
        "display-lg": ["48px", { lineHeight: "52px", letterSpacing: "-0.02em" }],
        "display-md": ["36px", { lineHeight: "44px", letterSpacing: "-0.02em" }],
        "display-sm": ["24px", { lineHeight: "28.8px", letterSpacing: "-0.02em" }],
        eyebrow: ["14px", { lineHeight: "14px", letterSpacing: "0.04em" }],
      },
      keyframes: {
        "slide-in": {
          "0%": { transform: "translateX(100%)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
        "slide-up": {
          "0%": { transform: "translateY(8px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        // Orbital arc trace animation for decorative SVG paths
        "orbital-trace": {
          "0%": { strokeDashoffset: "1000" },
          "100%": { strokeDashoffset: "0" },
        },
      },
      animation: {
        "slide-in": "slide-in 0.3s ease-out",
        "slide-up": "slide-up 0.25s ease-out",
        "orbital-trace": "orbital-trace 1.2s ease-out forwards",
      },
      spacing: {
        // Section vertical padding scale
        "section-desktop": "96px",
        "section-mobile": "48px",
      },
    },
  },
  plugins: [],
} satisfies Config;
