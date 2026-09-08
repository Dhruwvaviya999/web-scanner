import { API_BASE_URL, apiClient } from "@/lib/api-client";
import type {
  EndpointListResponse,
  FormListResponse,
} from "@/types/attack-surface";
import type { FindingListResponse } from "@/types/finding";
import type { ScanReport } from "@/types/report";
import type {
  CreateScanPayload,
  ListScansParams,
  Scan,
  ScanListResponse,
  ScanStats,
} from "@/types/scan";

export const scanService = {
  /** Creates the scan and waits for the probe to finish (see backend timeouts). */
  async create(payload: CreateScanPayload): Promise<Scan> {
    const { data } = await apiClient.post<Scan>("/scans", payload);
    return data;
  },

  async list(params: ListScansParams = {}): Promise<ScanListResponse> {
    const { data } = await apiClient.get<ScanListResponse>("/scans", { params });
    return data;
  },

  async stats(): Promise<ScanStats> {
    const { data } = await apiClient.get<ScanStats>("/scans/stats");
    return data;
  },

  async get(id: string): Promise<Scan> {
    const { data } = await apiClient.get<Scan>(`/scans/${id}`);
    return data;
  },

  /** Security findings for one scan, most severe first. */
  async findings(id: string): Promise<FindingListResponse> {
    const { data } = await apiClient.get<FindingListResponse>(`/scans/${id}/findings`);
    return data;
  },

  /** URLs the crawler reached, with their query parameter names. */
  async endpoints(id: string): Promise<EndpointListResponse> {
    const { data } = await apiClient.get<EndpointListResponse>(`/scans/${id}/endpoints`);
    return data;
  },

  /** Forms found on crawled pages. Discovery only — none were submitted. */
  async forms(id: string): Promise<FormListResponse> {
    const { data } = await apiClient.get<FormListResponse>(`/scans/${id}/forms`);
    return data;
  },

  /** The canonical report. Read-only: generating it re-runs nothing. */
  async report(id: string): Promise<ScanReport> {
    const { data } = await apiClient.get<ScanReport>(`/scans/${id}/report`);
    return data;
  },

  /** URL of the downloadable JSON report, for an anchor or window navigation. */
  reportDownloadUrl(id: string): string {
    return `${API_BASE_URL}/api/scans/${id}/report/json`;
  },

  async remove(id: string): Promise<void> {
    await apiClient.delete(`/scans/${id}`);
  },
};
