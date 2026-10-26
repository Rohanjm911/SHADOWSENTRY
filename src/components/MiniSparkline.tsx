import React, { useId } from "react";

interface MiniSparklineProps {
  data: number[];
  color?: string;
  width?: number;
  height?: number;
  ariaLabel?: string;
}

export const MiniSparkline: React.FC<MiniSparklineProps> = ({
  data,
  color = "var(--color-accent-primary)",
  width = 76,
  height = 24,
  ariaLabel = "Telemetry sparkline",
}) => {
  const gradientId = useId();

  // Ensure at least 6 points for a smooth visual curve
  const points = data.length >= 2 ? data : [1, 3, 2, 5, 4, 6];
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = max - min || 1;

  const paddingY = 3;
  const usableHeight = height - paddingY * 2;
  const stepX = width / (points.length - 1);

  const coords = points.map((val, idx) => {
    const x = idx * stepX;
    const normalized = (val - min) / range;
    const y = height - paddingY - normalized * usableHeight;
    return { x, y };
  });

  // Construct smooth SVG path
  let pathD = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;
  for (let i = 1; i < coords.length; i++) {
    const prev = coords[i - 1];
    const curr = coords[i];
    const cpX = (prev.x + curr.x) / 2;
    pathD += ` C ${cpX.toFixed(1)} ${prev.y.toFixed(1)}, ${cpX.toFixed(1)} ${curr.y.toFixed(1)}, ${curr.x.toFixed(1)} ${curr.y.toFixed(1)}`;
  }

  const lastPoint = coords[coords.length - 1];
  const areaD = `${pathD} L ${width} ${height} L 0 ${height} Z`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      style={{ overflow: "visible", flexShrink: 0 }}
      aria-label={ariaLabel}
      role="img"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={areaD} fill={`url(#${gradientId})`} />
      <path
        d={pathD}
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx={lastPoint.x} cy={lastPoint.y} r="2.2" fill={color} />
    </svg>
  );
};
