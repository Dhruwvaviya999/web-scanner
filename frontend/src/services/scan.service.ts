import { apiClient } from "@/lib/api-client";
import type { FindingListResponse } from "@/types/finding";
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

  async remove(id: string): Promise<void> {
    await apiClient.delete(`/scans/${id}`);
  },
};
