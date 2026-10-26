import React, { useState, useId, useRef, useMemo } from "react";
import { TrafficTimelinePoint, SessionStats } from "../types/stats";
import { formatBytes } from "../lib/formatters";
import { Activity, ShieldAlert, Zap } from "lucide-react";

interface TrafficTimelineChartProps {
  timeline: TrafficTimelinePoint[];
  sessionStats?: SessionStats;
  maxPackets?: number;
  isMonitoring?: boolean;
}

export const TrafficTimelineChart: React.FC<TrafficTimelineChartProps> = ({
  timeline,
  sessionStats,
  maxPackets: propMaxPackets,
  isMonitoring = true,
}) => {
  const [metric, setMetric] = useState<"packets" | "bytes">("packets");
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const chartId = useId().replace(/:/g, "_");

  // Sliding window normalization: ensure at least 25-30 continuous slots so the chart is never sparse
  const normalizedData = useMemo(() => {
    const TARGET_SLOTS = 30;
    if (!timeline || timeline.length === 0) {
      // Resting carrier wave
      return Array.from({ length: TARGET_SLOTS }, (_, i) => ({
        timestamp: new Date(Date.now() - (TARGET_SLOTS - 1 - i) * 1000).toISOString(),
        time_label: `-${TARGET_SLOTS - 1 - i}s`,
        packet_count: 0,
        byte_count: 0,
        event_count: 0,
      }));
    }

    if (timeline.length >= TARGET_SLOTS) {
      return timeline.slice(-TARGET_SLOTS);
    }

    // Pad leading entries with zero baseline so data flows naturally to the live head
    const padCount = TARGET_SLOTS - timeline.length;
    const padding = Array.from({ length: padCount }, (_, i) => ({
      timestamp: "",
      time_label: `-${TARGET_SLOTS - i}s`,
      packet_count: 0,
      byte_count: 0,
      event_count: 0,
    }));

    return [...padding, ...timeline];
  }, [timeline]);

  // Extract values based on active metric
  const values = useMemo(() => {
    return normalizedData.map((d) => (metric === "packets" ? d.packet_count : d.byte_count));
  }, [normalizedData, metric]);

  const peakVal = useMemo(() => {
    const rawMax = Math.max(...values, 0);
    if (metric === "packets") {
      return Math.max(rawMax, propMaxPackets || 10, 10);
    }
    return Math.max(rawMax, 1024 * 10); // minimum 10 KB for bytes
  }, [values, metric, propMaxPackets]);

  const midVal = Math.round(peakVal / 2);

  // SVG Dimension constants
  const svgWidth = 600;
  const svgHeight = 135;
  const padLeft = 46;
  const padRight = 14;
  const padTop = 14;
  const padBottom = 26;

  const graphWidth = svgWidth - padLeft - padRight;
  const graphHeight = svgHeight - padTop - padBottom;
  const baselineY = svgHeight - padBottom;

  // Calculate coordinates for each point
  const coords = useMemo(() => {
    const n = normalizedData.length;
    const stepX = graphWidth / Math.max(n - 1, 1);

    return normalizedData.map((point, i) => {
      const val = metric === "packets" ? point.packet_count : point.byte_count;
      const x = padLeft + i * stepX;
      const normalizedHeight = peakVal > 0 ? (val / peakVal) * graphHeight : 0;
      const y = baselineY - Math.min(graphHeight, Math.max(normalizedHeight, 0));
      return { x, y, point, val };
    });
  }, [normalizedData, metric, peakVal, graphWidth, graphHeight, baselineY, padLeft]);

  // Construct smooth cubic Bezier spline
  const { linePath, areaPath } = useMemo(() => {
    if (coords.length === 0) return { linePath: "", areaPath: "" };

    let line = `M ${coords[0].x.toFixed(1)} ${coords[0].y.toFixed(1)}`;
    for (let i = 1; i < coords.length; i++) {
      const prev = coords[i - 1];
      const curr = coords[i];
      const cpX = (prev.x + curr.x) / 2;
      line += ` C ${cpX.toFixed(1)} ${prev.y.toFixed(1)}, ${cpX.toFixed(1)} ${curr.y.toFixed(1)}, ${curr.x.toFixed(1)} ${curr.y.toFixed(1)}`;
    }

    const last = coords[coords.length - 1];
    const first = coords[0];
    const area = `${line} L ${last.x.toFixed(1)} ${baselineY} L ${first.x.toFixed(1)} ${baselineY} Z`;

    return { linePath: line, areaPath: area };
  }, [coords, baselineY]);

  // Active or latest telemetry stats
  const latestPoint = normalizedData[normalizedData.length - 1];
  const lastCoord = coords[coords.length - 1];
  const activeRateFormatted = metric === "packets"
    ? `${sessionStats?.packet_rate_per_sec ?? latestPoint?.packet_count ?? 0} pkts/s`
    : `${formatBytes(sessionStats?.byte_rate_per_sec ?? latestPoint?.byte_count ?? 0)}/s`;

  // Hover interaction handler
  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mouseX = ((e.clientX - rect.left) / rect.width) * svgWidth;

    if (mouseX < padLeft || mouseX > svgWidth - padRight) {
      setHoverIndex(null);
      return;
    }

    // Find closest coordinate
    let closestIdx = 0;
    let minDist = Infinity;
    coords.forEach((c, idx) => {
      const dist = Math.abs(c.x - mouseX);
      if (dist < minDist) {
        minDist = dist;
        closestIdx = idx;
      }
    });

    setHoverIndex(closestIdx);
  };

  const hoveredCoord = hoverIndex !== null ? coords[hoverIndex] : null;

  return (
    <div
      ref={containerRef}
      style={{
        backgroundColor: "var(--color-surface)",
        border: "1px solid var(--color-border)",
        borderRadius: "var(--radius-md)",
        padding: "16px",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        boxShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
      }}
    >
      {/* Header with Title, Mode Switcher, and Live Rate Pill */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: "12px",
          gap: "12px",
          flexWrap: "wrap",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Activity size={15} style={{ color: "var(--color-accent-primary)" }} />
            <h3 style={{ fontSize: "13px", fontWeight: 600, color: "var(--color-text-primary)", letterSpacing: "0.01em" }}>
              Traffic Activity Over Time
            </h3>
            {isMonitoring && (
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "5px",
                  padding: "1px 7px",
                  borderRadius: "10px",
                  backgroundColor: "rgba(56, 189, 248, 0.12)",
                  color: "var(--color-accent-primary)",
                  fontSize: "10px",
                  fontWeight: 600,
                  fontFamily: "var(--font-mono)",
                }}
              >
                <span
                  style={{
                    width: 5,
                    height: 5,
                    borderRadius: "50%",
                    backgroundColor: "var(--color-accent-primary)",
                    boxShadow: "0 0 6px var(--color-accent-primary)",
                  }}
                />
                LIVE • {activeRateFormatted}
              </span>
            )}
          </div>
          <p style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "2px" }}>
            Continuous sliding telemetry • Oscilloscope wave with telemetry crosshairs
          </p>
        </div>

        {/* Controls: Metric Toggle and Peak Display */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {/* Mode Switcher: Packets vs Bandwidth */}
          <div
            style={{
              display: "inline-flex",
              backgroundColor: "var(--color-surface-elevated)",
              padding: "2px",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--color-border-subtle)",
            }}
          >
            <button
              onClick={() => setMetric("packets")}
              style={{
                background: metric === "packets" ? "var(--color-accent-primary)" : "transparent",
                color: metric === "packets" ? "var(--color-text-on-accent)" : "var(--color-text-secondary)",
                border: "none",
                borderRadius: "3px",
                padding: "3px 8px",
                fontSize: "10.5px",
                fontWeight: 600,
                cursor: "pointer",
                fontFamily: "var(--font-mono)",
                transition: "all 0.15s ease",
              }}
              title="Show packets per second"
            >
              Packets
            </button>
            <button
              onClick={() => setMetric("bytes")}
              style={{
                background: metric === "bytes" ? "var(--color-accent-primary)" : "transparent",
                color: metric === "bytes" ? "var(--color-text-on-accent)" : "var(--color-text-secondary)",
                border: "none",
                borderRadius: "3px",
                padding: "3px 8px",
                fontSize: "10.5px",
                fontWeight: 600,
                cursor: "pointer",
                fontFamily: "var(--font-mono)",
                transition: "all 0.15s ease",
              }}
              title="Show volume bandwidth bytes per second"
            >
              Bytes
            </button>
          </div>

          {/* Peak Indicator */}
          <div
            style={{
              padding: "3px 8px",
              backgroundColor: "var(--color-surface-elevated)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--color-border-subtle)",
              fontSize: "11px",
              fontFamily: "var(--font-mono)",
              color: "var(--color-text-secondary)",
              display: "flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <Zap size={11} style={{ color: "var(--color-warning)" }} />
            <span>Peak:</span>
            <strong style={{ color: "var(--color-text-primary)" }}>
              {metric === "packets" ? `${peakVal} pkts` : formatBytes(peakVal)}
            </strong>
          </div>
        </div>
      </div>

      {/* Main SVG Telemetry Waveform View */}
      <div style={{ height: "140px", width: "100%", position: "relative" }}>
        <svg
          width="100%"
          height="100%"
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          preserveAspectRatio="none"
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setHoverIndex(null)}
          style={{ cursor: "crosshair", overflow: "visible" }}
        >
          <defs>
            {/* Luminous Area Fill Gradient */}
            <linearGradient id={`areaGrad_${chartId}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-accent-primary)" stopOpacity="0.32" />
              <stop offset="70%" stopColor="var(--color-accent-primary)" stopOpacity="0.06" />
              <stop offset="100%" stopColor="var(--color-accent-primary)" stopOpacity="0.0" />
            </linearGradient>

            {/* Neon Glow Filter */}
            <filter id={`glow_${chartId}`} x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Y-Axis Grid Lines & Tick Labels */}
          {/* Peak grid line */}
          <line
            x1={padLeft}
            y1={padTop}
            x2={svgWidth - padRight}
            y2={padTop}
            stroke="var(--color-border-subtle)"
            strokeWidth="1"
            strokeDasharray="4 4"
          />
          <text
            x={padLeft - 6}
            y={padTop + 3}
            textAnchor="end"
            fontSize="9"
            fill="var(--color-text-muted)"
            fontFamily="var(--font-mono)"
          >
            {metric === "packets" ? peakVal : formatBytes(peakVal)}
          </text>

          {/* Mid grid line */}
          <line
            x1={padLeft}
            y1={padTop + graphHeight / 2}
            x2={svgWidth - padRight}
            y2={padTop + graphHeight / 2}
            stroke="var(--color-border-subtle)"
            strokeWidth="1"
            strokeDasharray="4 4"
          />
          <text
            x={padLeft - 6}
            y={padTop + graphHeight / 2 + 3}
            textAnchor="end"
            fontSize="9"
            fill="var(--color-text-muted)"
            fontFamily="var(--font-mono)"
          >
            {metric === "packets" ? midVal : formatBytes(midVal)}
          </text>

          {/* Baseline grid line */}
          <line
            x1={padLeft}
            y1={baselineY}
            x2={svgWidth - padRight}
            y2={baselineY}
            stroke="var(--color-border)"
            strokeWidth="1"
          />
          <text
            x={padLeft - 6}
            y={baselineY + 3}
            textAnchor="end"
            fontSize="9"
            fill="var(--color-text-muted)"
            fontFamily="var(--font-mono)"
          >
            0
          </text>

          {/* Backdrop Cyber Equalizer Columns */}
          {coords.map((c, idx) => {
            const barWidth = Math.max(3, graphWidth / (coords.length * 1.5));
            const barHeight = Math.max(0, baselineY - c.y);
            const isHovered = hoverIndex === idx;

            return (
              <g key={idx}>
                <rect
                  x={c.x - barWidth / 2}
                  y={c.y}
                  width={barWidth}
                  height={barHeight}
                  fill="var(--color-accent-primary)"
                  opacity={isHovered ? 0.45 : 0.12}
                  rx="1"
                  style={{ transition: "opacity 0.15s ease" }}
                />
                {barHeight > 3 && (
                  <line
                    x1={c.x - barWidth / 2}
                    y1={c.y}
                    x2={c.x + barWidth / 2}
                    y2={c.y}
                    stroke="var(--color-accent-primary)"
                    strokeWidth="1.2"
                    opacity={isHovered ? 0.9 : 0.4}
                  />
                )}
              </g>
            );
          })}

          {/* Spline Area Fill */}
          {areaPath && <path d={areaPath} fill={`url(#areaGrad_${chartId})`} />}

          {/* Neon Glow Outer Spline Stroke */}
          {linePath && (
            <path
              d={linePath}
              fill="none"
              stroke="var(--color-accent-primary)"
              strokeWidth="4"
              opacity="0.25"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}

          {/* Main Spline Line Stroke */}
          {linePath && (
            <path
              d={linePath}
              fill="none"
              stroke="var(--color-accent-primary)"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              filter={`url(#glow_${chartId})`}
            />
          )}

          {/* Threat Event Incident Markers on Curve */}
          {coords.map((c, idx) => {
            if (c.point.event_count > 0) {
              return (
                <g key={`evt_${idx}`}>
                  <circle
                    cx={c.x}
                    cy={c.y}
                    r="4.5"
                    fill="var(--color-critical)"
                    stroke="#fff"
                    strokeWidth="1.2"
                  />
                  <circle
                    cx={c.x}
                    cy={c.y}
                    r="8"
                    fill="none"
                    stroke="var(--color-critical)"
                    strokeWidth="1"
                    opacity="0.7"
                  />
                </g>
              );
            }
            return null;
          })}

          {/* Live Telemetry Pulsing Node at Latest Point */}
          {lastCoord && isMonitoring && (
            <g>
              {/* Expanding Radar Ripple */}
              <circle
                cx={lastCoord.x}
                cy={lastCoord.y}
                r="3"
                fill="none"
                stroke="var(--color-accent-primary)"
                strokeWidth="1.5"
              >
                <animate attributeName="r" values="3; 13" dur="2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.85; 0" dur="2s" repeatCount="indefinite" />
              </circle>
              {/* Solid Core Dot */}
              <circle
                cx={lastCoord.x}
                cy={lastCoord.y}
                r="3.5"
                fill="var(--color-accent-primary)"
                stroke="var(--color-surface)"
                strokeWidth="1.5"
              />
            </g>
          )}

          {/* Interactive Hover Crosshair and Node */}
          {hoveredCoord && (
            <g>
              {/* Vertical scanning crosshair line */}
              <line
                x1={hoveredCoord.x}
                y1={padTop}
                x2={hoveredCoord.x}
                y2={baselineY}
                stroke="var(--color-accent-primary)"
                strokeWidth="1.2"
                strokeDasharray="3 3"
                opacity="0.85"
              />
              {/* Target reticle dot */}
              <circle
                cx={hoveredCoord.x}
                cy={hoveredCoord.y}
                r="5.5"
                fill="var(--color-surface)"
                stroke="var(--color-accent-primary)"
                strokeWidth="2.5"
              />
            </g>
          )}

          {/* X-Axis Time Labels */}
          <g>
            <text
              x={padLeft}
              y={svgHeight - 10}
              fontSize="9"
              fill="var(--color-text-muted)"
              fontFamily="var(--font-mono)"
            >
              -30s
            </text>
            <text
              x={padLeft + graphWidth * 0.33}
              y={svgHeight - 10}
              fontSize="9"
              fill="var(--color-text-muted)"
              fontFamily="var(--font-mono)"
              textAnchor="middle"
            >
              -20s
            </text>
            <text
              x={padLeft + graphWidth * 0.66}
              y={svgHeight - 10}
              fontSize="9"
              fill="var(--color-text-muted)"
              fontFamily="var(--font-mono)"
              textAnchor="middle"
            >
              -10s
            </text>
            <text
              x={svgWidth - padRight}
              y={svgHeight - 10}
              fontSize="9"
              fill="var(--color-accent-primary)"
              fontFamily="var(--font-mono)"
              textAnchor="end"
              fontWeight={600}
            >
              LIVE
            </text>
          </g>
        </svg>

        {/* Floating Glassmorphic Telemetry Tooltip HUD */}
        {hoveredCoord && (
          <div
            style={{
              position: "absolute",
              left: `${Math.min(
                Math.max((hoveredCoord.x / svgWidth) * 100, 15),
                82
              )}%`,
              top: `${Math.max(
                (hoveredCoord.y / svgHeight) * 100 - 35,
                10
              )}%`,
              transform: "translate(-50%, -100%)",
              backgroundColor: "rgba(15, 23, 42, 0.94)",
              backdropFilter: "blur(8px)",
              border: "1px solid var(--color-accent-primary)",
              borderRadius: "var(--radius-sm)",
              padding: "6px 10px",
              boxShadow: "0 6px 18px rgba(0, 0, 0, 0.55), 0 0 10px rgba(56, 189, 248, 0.2)",
              pointerEvents: "none",
              zIndex: 10,
              minWidth: "140px",
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                borderBottom: "1px solid var(--color-border-subtle)",
                paddingBottom: "4px",
                marginBottom: "4px",
              }}
            >
              <span style={{ fontSize: "10px", color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}>
                {hoveredCoord.point.time_label || "Active Second"}
              </span>
              <span
                style={{
                  fontSize: "9px",
                  padding: "1px 4px",
                  borderRadius: "2px",
                  backgroundColor: "rgba(56, 189, 248, 0.15)",
                  color: "var(--color-accent-primary)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                T-SLICE
              </span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "2px", fontSize: "11px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: "var(--color-text-secondary)" }}>Packets:</span>
                <strong style={{ color: "var(--color-text-primary)", fontFamily: "var(--font-mono)" }}>
                  {hoveredCoord.point.packet_count} pkts/s
                </strong>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ color: "var(--color-text-secondary)" }}>Bandwidth:</span>
                <strong style={{ color: "var(--color-accent-primary)", fontFamily: "var(--font-mono)" }}>
                  {formatBytes(hoveredCoord.point.byte_count)}/s
                </strong>
              </div>

              {hoveredCoord.point.event_count > 0 && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "4px",
                    marginTop: "3px",
                    paddingTop: "3px",
                    borderTop: "1px solid var(--color-border-subtle)",
                    color: "var(--color-critical)",
                    fontSize: "10px",
                    fontWeight: 600,
                  }}
                >
                  <ShieldAlert size={12} />
                  <span>{hoveredCoord.point.event_count} Security alerts at this second</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
