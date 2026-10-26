export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatPacketCount(count: number): string {
  return new Intl.NumberFormat("en-US").format(count);
}

export function formatTimestamp(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      fractionalSecondDigits: 3,
    });
  } catch {
    return isoString;
  }
}

export function formatDateTime(isoString: string | null | undefined): string {
  if (!isoString) return "—";
  try {
    const d = new Date(isoString);
    return d.toLocaleString("en-US", {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return isoString;
  }
}

export function formatDuration(seconds: number): string {
  if (seconds < 0) return "0s";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) {
    return `${h}h ${m.toString().padStart(2, "0")}m ${s.toString().padStart(2, "0")}s`;
  }
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

export function formatIp(ip: string | null, redact: boolean = false): string {
  if (!ip) return "—";
  if (!redact) return ip;
  // Redact last octet or host portion
  if (ip.includes(".")) {
    const parts = ip.split(".");
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
    }
  } else if (ip.includes(":")) {
    const parts = ip.split(":");
    if (parts.length > 2) {
      return `${parts[0]}:${parts[1]}:...:xxxx`;
    }
  }
  return ip;
}

export function formatConfidence(score: number): { percent: string; label: string } {
  const percent = Math.round(score * 100);
  let label = "Low";
  if (percent >= 85) label = "Very High";
  else if (percent >= 70) label = "High";
  else if (percent >= 50) label = "Moderate";
  return { percent: `${percent}%`, label };
}
