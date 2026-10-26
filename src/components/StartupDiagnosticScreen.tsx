import React, { useState, useEffect } from "react";
import {
  CheckCircle2,
  Loader2,
  ArrowRight,
  ShieldCheck,
  Radio,
  Activity,
  Database,
  ShieldAlert,
  FlaskConical,
  Circle,
  Zap,
} from "lucide-react";
import { soundEffects } from "../lib/soundEffects";

interface StartupDiagnosticScreenProps {
  onComplete: () => void;
  onFading?: () => void;
  driverName?: string;
  interfaceCount?: number;
}

interface DiagnosticModule {
  id: string;
  name: string;
  description: string;
  icon: React.ElementType;
  activatesAtMs: number;
}

const SPLASH_DURATION_MS = 7000;

const MODULES: DiagnosticModule[] = [
  {
    id: "winsock",
    name: "WinSock 2 Raw Socket Ingestion",
    description: "Host AF_INET interface bound for wire-speed packet capture",
    icon: Radio,
    activatesAtMs: 1200,
  },
  {
    id: "npcap",
    name: "Npcap Promiscuous Sniffer",
    description: "wpcap.dll Layer-2 Ethernet & ARP frame interception",
    icon: Activity,
    activatesAtMs: 2500,
  },
  {
    id: "sqlite",
    name: "Local SQLite Forensic Storage",
    description: "Mounting zero-telemetry database in high-throughput WAL mode",
    icon: Database,
    activatesAtMs: 3800,
  },
  {
    id: "rules",
    name: "Heuristic Threat Engine (10 Rules)",
    description: "Multi-port scan, burst surge, DGA entropy & rogue gateway filters",
    icon: ShieldAlert,
    activatesAtMs: 5100,
  },
  {
    id: "honeypot",
    name: "Honeypot Deception Core (:8088 / :8443 / :2222)",
    description: "Isolated loopback decoy traps armed against lateral movement",
    icon: FlaskConical,
    activatesAtMs: 6400,
  },
];

export const StartupDiagnosticScreen: React.FC<StartupDiagnosticScreenProps> = ({
  onComplete,
  onFading,
  driverName = "Windows Raw Socket",
  interfaceCount = 1,
}) => {
  const onCompleteRef = React.useRef(onComplete);
  onCompleteRef.current = onComplete;
  const onFadingRef = React.useRef(onFading);
  onFadingRef.current = onFading;

  const [activeModuleIndex, setActiveModuleIndex] = useState(0);
  const [completedModuleIds, setCompletedModuleIds] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const [secondsRemaining, setSecondsRemaining] = useState(7);
  const [isDone, setIsDone] = useState(false);

  useEffect(() => {
    // Futuristic boot chime on application launch
    soundEffects.playBootChime();

    const timers: ReturnType<typeof setTimeout>[] = [];

    // Activate each module sequentially one-by-one across the 7 seconds
    MODULES.forEach((mod, index) => {
      const timer = setTimeout(() => {
        setCompletedModuleIds((prev) => (prev.includes(mod.id) ? prev : [...prev, mod.id]));
        setActiveModuleIndex(index + 1);
        soundEffects.playDiagnosticTick();
      }, mod.activatesAtMs);
      timers.push(timer);
    });

    // 60fps butter-smooth progress interpolation (0% -> 100% in 7000ms)
    const startTime = Date.now();
    const progressInterval = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const current = Math.min(100, Math.round((elapsed / SPLASH_DURATION_MS) * 100));
      setProgress(current);
      const remaining = Math.max(0, Math.ceil((SPLASH_DURATION_MS - elapsed) / 1000));
      setSecondsRemaining(remaining);

      if (elapsed >= SPLASH_DURATION_MS) {
        clearInterval(progressInterval);
      }
    }, 25);

    // Auto-transition to dashboard at 7000ms with a silky 850ms cinematic cross-dissolve
    const finalTimer = setTimeout(() => {
      setIsDone(true);
      if (onFadingRef.current) {
        onFadingRef.current();
      }
      setTimeout(() => {
        onCompleteRef.current();
      }, 880);
    }, SPLASH_DURATION_MS);
    timers.push(finalTimer);

    return () => {
      timers.forEach(clearTimeout);
      clearInterval(progressInterval);
    };
  }, []);

  const allCompleted = completedModuleIds.length >= MODULES.length;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 99999,
        backgroundColor: "#080D16",
        backgroundImage: "radial-gradient(ellipse at 50% 30%, rgba(53, 201, 138, 0.12) 0%, rgba(8, 13, 22, 0.98) 75%)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        transition: "opacity 0.85s cubic-bezier(0.16, 1, 0.3, 1), transform 0.85s cubic-bezier(0.16, 1, 0.3, 1), filter 0.85s cubic-bezier(0.16, 1, 0.3, 1)",
        opacity: isDone ? 0 : 1,
        transform: isDone ? "scale(1.035)" : "scale(1)",
        filter: isDone ? "blur(12px) brightness(1.08)" : "blur(0px) brightness(1)",
        willChange: "opacity, transform, filter",
        pointerEvents: isDone ? "none" : "auto",
        userSelect: "none",
        padding: "20px",
        overflowY: "auto",
      }}
    >
      {/* Top Header Strip with Status and Skip Action */}
      <div
        style={{
          position: "absolute",
          top: "16px",
          left: "24px",
          right: "24px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span
            style={{
              width: "8px",
              height: "8px",
              borderRadius: "50%",
              backgroundColor: "var(--color-success)",
              boxShadow: "0 0 10px var(--color-success)",
              display: "inline-block",
            }}
          />
          <span
            style={{
              fontSize: "11px",
              fontFamily: "var(--font-mono)",
              color: "var(--color-text-secondary)",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
          >
            SHADOWSENTRY // SEQUENTIAL SUBSYSTEM INITIALIZATION
          </span>
        </div>

        <div
          style={{
            fontSize: "10.5px",
            fontFamily: "var(--font-mono)",
            color: "var(--color-text-muted)",
            letterSpacing: "0.06em",
          }}
        >
          SECURE HOST ENGINE // V0.1.0
        </div>
      </div>

      {/* Main Container */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          maxWidth: "580px",
          width: "100%",
          gap: "14px",
          margin: "auto",
        }}
      >
        {/* Animated Mascot / Splash GIF Container */}
        <div
          style={{
            position: "relative",
            width: "150px",
            height: "150px",
            borderRadius: "16px",
            padding: "6px",
            background: "linear-gradient(145deg, rgba(53, 201, 138, 0.35), rgba(244, 63, 94, 0.35), rgba(15, 23, 42, 0.9))",
            boxShadow: "0 0 35px rgba(53, 201, 138, 0.25), 0 0 60px rgba(244, 63, 94, 0.16)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div
            style={{
              width: "100%",
              height: "100%",
              borderRadius: "12px",
              backgroundColor: "#0B1120",
              overflow: "hidden",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <img
              src="/splash.gif"
              alt="SHADOWSENTRY Startup Animation"
              style={{
                width: "100%",
                height: "100%",
                objectFit: "contain",
              }}
            />
          </div>
        </div>

        {/* Title */}
        <div style={{ textAlign: "center" }}>
          <h1
            style={{
              fontSize: "22px",
              fontWeight: 800,
              letterSpacing: "0.14em",
              color: "#FFFFFF",
              margin: 0,
              textShadow: "0 0 16px rgba(53, 201, 138, 0.4)",
            }}
          >
            SHADOWSENTRY
          </h1>
          <div
            style={{
              fontSize: "11.5px",
              color: "var(--color-text-secondary)",
              letterSpacing: "0.06em",
              marginTop: "2px",
              fontWeight: 500,
            }}
          >
            Invisible Threats. Visible Intelligence.
          </div>
        </div>

        {/* Sequential Module Activation Stack */}
        <div
          style={{
            width: "100%",
            backgroundColor: "rgba(15, 23, 42, 0.75)",
            border: "1px solid var(--color-border)",
            borderRadius: "var(--radius-md)",
            padding: "12px 14px",
            backdropFilter: "blur(10px)",
            display: "flex",
            flexDirection: "column",
            gap: "7px",
            boxShadow: "0 12px 32px rgba(0, 0, 0, 0.45)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
            <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--color-text-muted)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Core Security Modules (Sequential Ingestion):
            </span>
            <span
              style={{
                fontSize: "11px",
                fontFamily: "var(--font-mono)",
                color: allCompleted ? "var(--color-success)" : "var(--color-accent-primary)",
                fontWeight: 700,
                backgroundColor: allCompleted ? "rgba(52, 211, 153, 0.15)" : "rgba(56, 189, 248, 0.12)",
                padding: "2px 8px",
                borderRadius: "10px",
              }}
            >
              {completedModuleIds.length} / {MODULES.length} ARMED
            </span>
          </div>

          {/* Module Rows */}
          {MODULES.map((mod, index) => {
            const isCompleted = completedModuleIds.includes(mod.id);
            const isInitializing = !isCompleted && index === activeModuleIndex;
            const isPending = !isCompleted && !isInitializing;
            const Icon = mod.icon;

            return (
              <div
                key={mod.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "8px 12px",
                  borderRadius: "var(--radius-sm)",
                  backgroundColor: isCompleted
                    ? "rgba(16, 38, 30, 0.75)"
                    : isInitializing
                    ? "rgba(14, 30, 48, 0.85)"
                    : "rgba(11, 17, 32, 0.5)",
                  border: isCompleted
                    ? "1px solid rgba(52, 211, 153, 0.45)"
                    : isInitializing
                    ? "1px solid var(--color-accent-primary)"
                    : "1px solid rgba(255, 255, 255, 0.05)",
                  boxShadow: isInitializing
                    ? "0 0 14px rgba(56, 189, 248, 0.25)"
                    : isCompleted
                    ? "0 0 10px rgba(52, 211, 153, 0.12)"
                    : "none",
                  transition: "all 0.24s cubic-bezier(0.16, 1, 0.3, 1)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div
                    style={{
                      width: "28px",
                      height: "28px",
                      borderRadius: "var(--radius-sm)",
                      backgroundColor: isCompleted
                        ? "rgba(52, 211, 153, 0.18)"
                        : isInitializing
                        ? "rgba(56, 189, 248, 0.18)"
                        : "rgba(255, 255, 255, 0.04)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: isCompleted
                        ? "var(--color-success)"
                        : isInitializing
                        ? "var(--color-accent-primary)"
                        : "var(--color-text-muted)",
                      transition: "all 0.24s ease",
                    }}
                  >
                    <Icon size={15} />
                  </div>
                  <div>
                    <div
                      style={{
                        fontSize: "12px",
                        fontWeight: 600,
                        color: isCompleted
                          ? "var(--color-text-primary)"
                          : isInitializing
                          ? "var(--color-accent-primary)"
                          : "var(--color-text-muted)",
                        transition: "color 0.24s ease",
                      }}
                    >
                      {mod.name}
                    </div>
                    <div style={{ fontSize: "10px", color: isCompleted ? "var(--color-text-secondary)" : "var(--color-text-muted)" }}>
                      {mod.description}
                    </div>
                  </div>
                </div>

                {/* Status Badge */}
                <div>
                  {isCompleted && (
                    <span
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "5px",
                        fontSize: "10.5px",
                        fontFamily: "var(--font-mono)",
                        fontWeight: 700,
                        color: "var(--color-success)",
                        backgroundColor: "rgba(52, 211, 153, 0.14)",
                        border: "1px solid rgba(52, 211, 153, 0.4)",
                        padding: "2px 8px",
                        borderRadius: "4px",
                      }}
                    >
                      <CheckCircle2 size={12} />
                      <span>ONLINE</span>
                    </span>
                  )}

                  {isInitializing && (
                    <span
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "5px",
                        fontSize: "10.5px",
                        fontFamily: "var(--font-mono)",
                        fontWeight: 700,
                        color: "var(--color-accent-primary)",
                        backgroundColor: "rgba(56, 189, 248, 0.14)",
                        border: "1px solid var(--color-accent-primary)",
                        padding: "2px 8px",
                        borderRadius: "4px",
                      }}
                    >
                      <Loader2 size={12} className="spin" />
                      <span>INITIALIZING...</span>
                    </span>
                  )}

                  {isPending && (
                    <span
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "5px",
                        fontSize: "10px",
                        fontFamily: "var(--font-mono)",
                        color: "var(--color-text-muted)",
                        backgroundColor: "rgba(255, 255, 255, 0.03)",
                        border: "1px solid rgba(255, 255, 255, 0.08)",
                        padding: "2px 7px",
                        borderRadius: "4px",
                      }}
                    >
                      <Circle size={8} />
                      <span>STANDBY</span>
                    </span>
                  )}
                </div>
              </div>
            );
          })}

          {/* Bottom Progress Bar & Countdown */}
          <div style={{ marginTop: "6px", display: "flex", flexDirection: "column", gap: "5px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px" }}>
              <span
                style={{
                  color: allCompleted ? "var(--color-success)" : "var(--color-text-secondary)",
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  gap: "5px",
                }}
              >
                {allCompleted ? (
                  <>
                    <Zap size={13} style={{ color: "var(--color-success)" }} />
                    <span>ALL SYSTEMS OPERATIONAL // LAUNCHING SOC...</span>
                  </>
                ) : (
                  <span>INITIALIZING DEFENSE LAYERS...</span>
                )}
              </span>
              <span
                className="font-mono"
                style={{
                  color: allCompleted ? "var(--color-success)" : "var(--color-accent-primary)",
                  fontWeight: 700,
                }}
              >
                {secondsRemaining > 0 ? `${secondsRemaining}s (${progress}%)` : "ARMED"}
              </span>
            </div>

            <div
              style={{
                width: "100%",
                height: "5px",
                backgroundColor: "rgba(255, 255, 255, 0.08)",
                borderRadius: "3px",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${progress}%`,
                  height: "100%",
                  background: allCompleted
                    ? "var(--color-success)"
                    : "linear-gradient(90deg, #35C98A, #38BDF8, #F43F5E)",
                  boxShadow: `0 0 10px ${allCompleted ? "var(--color-success)" : "rgba(56, 189, 248, 0.6)"}`,
                  transition: "width 0.05s linear",
                }}
              />
            </div>
          </div>
        </div>

        {/* Footer Hardware Info */}
        <div style={{ fontSize: "10.5px", color: "var(--color-text-muted)", display: "flex", alignItems: "center", gap: "6px" }}>
          <ShieldCheck size={13} style={{ color: "var(--color-success)" }} />
          <span>Active Driver: {driverName} | {interfaceCount} interface(s) detected | Zero-cloud telemetry</span>
        </div>
      </div>
    </div>
  );
};
