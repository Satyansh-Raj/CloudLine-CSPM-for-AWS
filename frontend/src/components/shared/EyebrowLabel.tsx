interface Props {
  children: string;
  className?: string;
}

export default function EyebrowLabel({
  children,
  className = "",
}: Props) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-eyebrow font-medium tracking-eyebrow uppercase text-slate-gray ${className}`}
    >
      <span
        aria-hidden
        className="text-light-signal leading-none"
      >
        •
      </span>
      {children}
    </span>
  );
}
