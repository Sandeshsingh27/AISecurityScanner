import type { ScanRequest, SecurityScanReport } from "./types";

const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || "";

async function parseErrorResponse(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const json = (await response.json()) as Record<string, unknown>;
    return (json.message as string) || (json.error as string) || JSON.stringify(json);
  }
  return await response.text();
}

export async function requestScan(request: ScanRequest): Promise<SecurityScanReport> {
  const response = await fetch(`${BASE_URL}/api/scans/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(request)
  });

  if (!response.ok) {
    const message = await parseErrorResponse(response);
    throw new Error(`Scan failed: ${message}`);
  }

  return (await response.json()) as SecurityScanReport;
}

