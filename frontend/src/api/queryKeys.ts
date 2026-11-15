export const queryKeys = {
  consent: {
    current: ["consent", "current"] as const,
    version: ["consent", "version"] as const,
  },
  sources: {
    all: ["sources"] as const,
    page: (offset: number) => ["sources", "page", offset] as const,
  },
  scans: {
    all: ["scans"] as const,
    detail: (scanId: string) => ["scans", scanId] as const,
    findings: (scanId: string) => ["scans", scanId, "findings"] as const,
    score: (scanId: string) => ["scans", scanId, "score"] as const,
    graph: (scanId: string) => ["scans", scanId, "graph"] as const,
    recommendations: (scanId: string) => ["scans", scanId, "recommendations"] as const,
  },
  monitoring: {
    timeline: (monitorId: string) => ["monitoring", monitorId, "timeline"] as const,
  },
  audit: {
    entries: ["privacy", "audit"] as const,
    integrity: ["privacy", "audit", "integrity"] as const,
  },
} as const;
