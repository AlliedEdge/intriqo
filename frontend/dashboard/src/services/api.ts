/**
 * Intriqo Control Plane API Client
 * Interfaces with the Python FastAPI control plane layer.
 */

export interface SystemStatus {
  status: string;
  version: string;
  uptime_seconds?: number;
}

export async function fetchHealth(): Promise<SystemStatus> {
  const response = await fetch('/api/v1/health');
  if (!response.ok) {
    throw new Error(`API health check failed: ${response.statusText}`);
  }
  return response.json();
}
