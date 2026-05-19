interface Props {
  dark?: boolean;
  className?: string;
}

export default function CloudLineLogo({ dark = false, className = "" }: Props) {
  const cloud = dark ? "#e8e0d8" : "#252422";
  const textMain = dark ? "#e8e0d8" : "#252422";
  const textAccent = dark ? "#E05A1A" : "#C94A0A";

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="100 39 675 247"
      className={className}
      aria-label="CloudLine"
      role="img"
      style={{ background: "transparent" }}
    >
      <defs>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=Sofia+Sans:wght@700&display=swap');`}</style>
      </defs>

      <g transform="translate(105,204) scale(0.033,-0.033)">
        <path
          d="M1927 2825 c-392 -66 -715 -342 -841 -718 -22 -68 -35 -137 -52 -293 l-5 -41 -88 5 c-235 13 -475 -74 -654 -239 -159 -145 -259 -353 -282 -586 -8 -84 8 -229 37 -323 89 -289 327 -513 637 -599 l96 -26 1793 -3 c1773 -2 1794 -2 1879 18 304 72 522 328 550 645 17 198 -77 429 -230 571 -123 114 -251 169 -429 187 l-108 11 0 42 c0 23 -6 75 -14 116 -68 346 -317 605 -666 694 -108 27 -316 26 -421 -3 l-77 -20 -60 91 c-67 102 -174 215 -267 281 -229 164 -529 235 -798 190z"
          fill={cloud}
        />
      </g>

      <rect x="105" y="213" width="170" height="12" rx="6" fill="#C94A0A" />

      <text
        x="300"
        y="190"
        fontFamily="'Sofia Sans', 'Arial Black', sans-serif"
        fontSize="95"
        fontWeight="700"
        letterSpacing="-1"
      >
        <tspan fill={textMain}>Cloud</tspan>
        <tspan fill={textAccent}>Line</tspan>
      </text>
    </svg>
  );
}
