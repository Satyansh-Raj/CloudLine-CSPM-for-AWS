/**
 * MultiRingDonut
 * -------------
 * Premium concentric-ring donut chart (one ring per category).
 * Uses plain SVG — no Recharts dependency.
 *
 * Props:
 *   rings      – array of { label, value, max, color } where value/max [0,1] sets fill %
 *   center     – text rendered in the middle (e.g. "65%")
 *   subCenter  – smaller line below center (e.g. "compliance")
 *   size       – outer SVG size in px (default 180)
 *   ringWidth  – stroke width of each ring (default 14)
 *   gap        – gap between rings in px (default 20)
 */

interface Ring {
    label: string;
    value: number;   // actual number for legend display
    pct: number;     // 0‒100 — fill percentage for this ring
    color: string;   // hex or rgb
}

interface Props {
    rings: Ring[];
    center?: string;
    subCenter?: string;
    size?: number;
    ringWidth?: number;
    gap?: number;
    /** Appended to each legend value, e.g. "%" → shows "21%" */
    valueSuffix?: string;
}

export default function MultiRingDonut({
    rings,
    center,
    subCenter,
    size = 180,
    ringWidth = 13,
    gap = 19,
    valueSuffix = "",
}: Props) {
    const cx = size / 2;
    const cy = size / 2;

    // Outermost ring gets the largest radius; inner rings get smaller
    const outerRadius = cx - ringWidth / 2 - 4;

    return (
        /* color: inherit lets SVG text fill="currentColor" pick up this div's colour */
        <div className="flex flex-col items-center gap-3 text-gray-900 dark:text-white">
            <svg
                width={size}
                height={size}
                viewBox={`0 0 ${size} ${size}`}
                style={{ overflow: "visible" }}
                aria-hidden="true"
            >
                {rings.map((ring, i) => {
                    const radius = outerRadius - i * gap;
                    if (radius <= 0) return null;

                    const circumference = 2 * Math.PI * radius;
                    const fill = Math.min(100, Math.max(0, ring.pct));
                    const dashLen = (fill / 100) * circumference;
                    const gapLen = circumference - dashLen;

                    // Start from top (−90°)
                    const rotate = -90;

                    return (
                        <g key={ring.label}>
                            {/* Track (background ring) */}
                            <circle
                                cx={cx}
                                cy={cy}
                                r={radius}
                                fill="none"
                                stroke={ring.color}
                                strokeWidth={ringWidth}
                                strokeOpacity={0.12}
                            />
                            {/* Filled arc */}
                            <circle
                                cx={cx}
                                cy={cy}
                                r={radius}
                                fill="none"
                                stroke={ring.color}
                                strokeWidth={ringWidth}
                                strokeLinecap="round"
                                strokeDasharray={`${dashLen} ${gapLen}`}
                                transform={`rotate(${rotate}, ${cx}, ${cy})`}
                                style={{ transition: "stroke-dasharray 0.6s ease" }}
                            />
                        </g>
                    );
                })}

                {/* Centre text — fill="currentColor" inherits from parent div */}
                {center && (
                    <text
                        x={cx}
                        y={cy + 7}
                        textAnchor="middle"
                        fontSize={size * 0.155}
                        fontWeight="700"
                        fill="currentColor"
                    >
                        {center}
                    </text>
                )}
                {subCenter && (
                    <text
                        x={cx}
                        y={cy + 7 + size * 0.085}
                        textAnchor="middle"
                        fontSize={size * 0.076}
                        fill="currentColor"
                        opacity={0.45}
                    >
                        {subCenter}
                    </text>
                )}
            </svg>

            {/* Legend */}
            <div className="flex flex-wrap justify-center gap-x-4 gap-y-1.5">
                {rings.map((ring) => (
                    <div key={ring.label} className="flex items-center gap-1.5 text-[11px]">
                        <span
                            className="w-2.5 h-2.5 rounded-full shrink-0"
                            style={{ backgroundColor: ring.color }}
                        />
                        <span className="text-gray-500 dark:text-gray-400">{ring.label}</span>
                        <span className="font-semibold text-gray-700 dark:text-gray-200 tabular-nums ml-0.5">
                            {ring.value}{valueSuffix}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
}
