interface Props {
  children: string;
  className?: string;
}

export default function GhostHeadline({
  children,
  className = "",
}: Props) {
  return (
    <span
      aria-hidden
      className={`absolute select-none text-display-xl font-extrabold text-ghost-cream pointer-events-none leading-none ${className}`}
    >
      {children}
    </span>
  );
}
