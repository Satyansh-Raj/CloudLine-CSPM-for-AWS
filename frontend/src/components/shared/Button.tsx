import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "ink" | "outline" | "orange";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  intent?: "default" | "consent";
  children: ReactNode;
}

const variantClass: Record<Variant, string> = {
  ink: "bg-ink-black text-lifted-cream hover:opacity-90 active:scale-[0.98]",
  outline:
    "border border-ink-black text-ink-black bg-transparent hover:bg-ink-black hover:text-lifted-cream",
  orange:
    "bg-signal-orange text-white hover:bg-clay-brown active:scale-[0.98]",
};

export default function Button({
  variant = "ink",
  intent = "default",
  children,
  className = "",
  ...props
}: Props) {
  const v = intent === "consent" ? "orange" : variant;
  return (
    <button
      className={`inline-flex items-center justify-center px-6 py-3 rounded-btn font-medium tracking-tight text-sm transition-all disabled:opacity-40 ${variantClass[v]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
