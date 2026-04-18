import type { ReactNode } from "react";

type CardVariant = "stadium" | "pill";

interface Props {
  variant?: CardVariant;
  children: ReactNode;
  className?: string;
}

export default function Card({
  variant = "stadium",
  children,
  className = "",
}: Props) {
  const radius =
    variant === "pill" ? "rounded-pill" : "rounded-hero";
  return (
    <div
      className={`bg-lifted-cream shadow-elev-2 ${radius} p-6 ${className}`}
    >
      {children}
    </div>
  );
}
