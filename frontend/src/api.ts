import type { ScanRequest, SecurityScanReport } from "./types";

const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || "";
const REPORT_ENDPOINT = `${BASE_URL}/api/scans/report`;

function logApi(message: string, detail?: unknown): void {
  if (detail === undefined) {
    console.info(`[api] ${message}`);
    return;
  }
  console.info(`[api] ${message}`, detail);
}

async function parseErrorResponse(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const json = (await response.json()) as Record<string, unknown>;
    return (json.message as string) || (json.error as string) || JSON.stringify(json);
  }
  return await response.text();
}

export async function requestScan(request: ScanRequest): Promise<SecurityScanReport> {
  logApi(`-> POST ${REPORT_ENDPOINT}`);
  const response = await fetch(REPORT_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(request)
  });
  logApi(`<-- ${response.status} POST ${REPORT_ENDPOINT}`);

  if (!response.ok) {
    const message = await parseErrorResponse(response);
    console.error(`[api] xx ${response.status} POST ${REPORT_ENDPOINT}: ${message}`);
    throw new Error(`Scan failed: ${message}`);
  }

  return (await response.json()) as SecurityScanReport;
}

