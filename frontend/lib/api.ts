import axios from "axios";
import { ScanResponse, WatchlistResponse, AlertResponse, DashboardStats } from "../types";

let base = process.env.NEXT_PUBLIC_API_URL || "/_/backend/api/v1";
if (base && base.startsWith('http') && !base.endsWith('/api/v1')) {
    base = base.replace(/\/$/, '') + '/api/v1';
}
const API_BASE_URL = base;

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 90000, // 90 seconds timeout to accommodate full parallel OSINT checks
});

export const api = {
  // Analyze indicator
  analyzeIndicator: async (indicator: string, type: "ip" | "url" | "domain" | "hash"): Promise<ScanResponse> => {
    // Determine exact endpoint path based on type
    const endpoint = `/analyze/${type}`;
    const response = await apiClient.post<ScanResponse>(endpoint, {
      indicator,
      type,
    });
    return response.data;
  },

  // Get scan report by ID
  getScanReport: async (scanId: string): Promise<ScanResponse> => {
    const response = await apiClient.get<ScanResponse>(`/analyze/scan/${scanId}`);
    return response.data;
  },


  // Telemetry Dashboard
  getDashboardStats: async (): Promise<DashboardStats> => {
    const response = await apiClient.get<DashboardStats>("/dashboard/stats");
    return response.data;
  },
  
  getScanActivity: async () => {
    const response = await apiClient.get("/dashboard/activity");
    return response.data;
  },

  getTopIocs: async () => {
    const response = await apiClient.get("/dashboard/top-iocs");
    return response.data;
  },

  getApiHealth: async () => {
    const response = await apiClient.get("/dashboard/api-health");
    return response.data;
  },

  // Watchlist Operations
  getWatchlist: async (): Promise<WatchlistResponse[]> => {
    const response = await apiClient.get<WatchlistResponse[]>("/watchlist/");
    return response.data;
  },

  addToWatchlist: async (indicator: string, type: string, notes: string = "") => {
    const response = await apiClient.post<WatchlistResponse>("/watchlist/", {
      indicator,
      type,
      notes,
    });
    return response.data;
  },

  removeFromWatchlist: async (indicator: string) => {
    await apiClient.delete(`/watchlist/${encodeURIComponent(indicator)}`);
  },

  updateWatchlistItem: async (indicator: string, data: any) => {
    const response = await apiClient.patch(`/watchlist/${encodeURIComponent(indicator)}`, data);
    return response.data;
  },

  scanWatchlistAll: async () => {
    const response = await apiClient.post("/watchlist/scan-all");
    return response.data;
  },

  // Alerts Management
  getAlerts: async (): Promise<AlertResponse[]> => {
    const response = await apiClient.get<AlertResponse[]>("/watchlist/alerts");
    return response.data;
  },

  dismissAlert: async (alertId: number): Promise<AlertResponse> => {
    const response = await apiClient.put<AlertResponse>(`/watchlist/alerts/${alertId}`, {
      is_dismissed: true,
    });
    return response.data;
  },

  // Advanced OSINT Endpoints
  getReverseDns: async (ip: string) => {
    const response = await apiClient.get(`/osint/reverse-dns/${ip}`);
    return response.data;
  },
  
  getPorts: async (ip: string) => {
    const response = await apiClient.get(`/osint/ports/${ip}`);
    return response.data;
  },
  
  getWhois: async (domain: string) => {
    const response = await apiClient.get(`/osint/whois/${domain}`);
    return response.data;
  },

  getSsl: async (domain: string) => {
    const response = await apiClient.get(`/osint/ssl/${domain}`);
    return response.data;
  },

  getSubdomains: async (domain: string) => {
    const response = await apiClient.get(`/osint/subdomains/${domain}`);
    return response.data;
  },

  getAsnDetails: async (ip: string) => {
    const response = await apiClient.get(`/osint/asn/${ip}`);
    return response.data;
  },

  checkEmailBreaches: async (email: string) => {
    const response = await apiClient.get(`/osint/breach/${email}`);
    return response.data;
  },

  getCves: async (keyword: string) => {
    const response = await apiClient.get(`/osint/cve/${keyword}`);
    return response.data;
  },

  bulkScan: async (indicators: string[]) => {
    const response = await apiClient.post(`/osint/bulk-scan`, { indicators });
    return response.data;
  },

  getDnsRecords: async (domain: string) => {
    const response = await apiClient.get(`/osint/dns/${domain}`);
    return response.data;
  },

  getShodan: async (ip: string) => {
    const response = await apiClient.get(`/osint/shodan/${ip}`);
    return response.data;
  },

  getDarkWeb: async (indicator: string) => {
    const response = await apiClient.get(`/osint/darkweb/${indicator}`);
    return response.data;
  },

  getWebVulns: async (domain: string) => {
    const response = await apiClient.get(`/osint/web-vulns/${domain}`);
    return response.data;
  },

  getTechStack: async (domain: string) => {
    const response = await apiClient.get(`/osint/tech-stack/${domain}`);
    return response.data;
  },

  // Export URLs (these return relative download paths)
  getExportUrl: (scanId: string, format: "pdf" | "csv" | "json"): string => {
    return `${API_BASE_URL}/export/${scanId}?format=${format}`;
  },

  getBulkExportUrl: (format: "csv" | "json" = "csv"): string => {
    return `${API_BASE_URL}/export/watchlist/bulk?format=${format}`;
  },

  getRssFeedUrl: (): string => {
    return `${API_BASE_URL}/export/feed/rss`;
  },

  exportStix: async (scanId: string) => {
    const response = await apiClient.get(`/export/stix/${scanId}`);
    return response.data;
  },

  getThreatActors: async () => {
    const response = await apiClient.get(`/threat-actors/`);
    return response.data;
  },

  syncThreatActors: async () => {
    const response = await apiClient.post(`/threat-actors/sync`);
    return response.data;
  },

  // Campaigns
  getCampaigns: async () => {
    const response = await apiClient.get(`/campaigns/`);
    return response.data;
  },
  getCampaign: async (id: string) => {
    const response = await apiClient.get(`/campaigns/${id}`);
    return response.data;
  },
  createCampaign: async (name: string, description?: string) => {
    const response = await apiClient.post(`/campaigns/`, { name, description });
    return response.data;
  },
  deleteCampaign: async (id: string) => {
    const response = await apiClient.delete(`/campaigns/${id}`);
    return response.data;
  },
  addIOCToCampaign: async (campaignId: string, scanId: string) => {
    const response = await apiClient.post(`/campaigns/${campaignId}/iocs`, { scan_id: scanId });
    return response.data;
  },
  removeIOCFromCampaign: async (campaignId: string, scanId: string) => {
    const response = await apiClient.delete(`/campaigns/${campaignId}/iocs/${scanId}`);
    return response.data;
  },

  // Community Notes
  getNotes: async (indicator: string) => {
    const response = await apiClient.get(`/notes/${encodeURIComponent(indicator)}`);
    return response.data;
  },
  addNote: async (indicator: string, text: string, author?: string) => {
    const response = await apiClient.post(`/notes/`, { indicator, text, author });
    return response.data;
  },
  upvoteNote: async (noteId: number) => {
    const response = await apiClient.post(`/notes/${noteId}/upvote`);
    return response.data;
  },

  // Health check
  healthCheck: async () => {
    const response = await apiClient.get(`/health`);
    return response.data;
  },

  // AI Chat
  askAi: async (message: string, history: any[] = [], model: string = "openai/gpt-oss-120b") => {
    const response = await apiClient.post(`/chat`, { message, history, model });
    return response.data;
  },

  // AI Chat with Image
  askAiWithImage: async (message: string, file: File) => {
    const formData = new FormData();
    formData.append("message", message);
    formData.append("file", file);
    
    const response = await apiClient.post(`/chat/image`, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
    return response.data;
  },

  // Tools
  toolsEmailHeaders: async (rawHeaders: string) => {
    const response = await apiClient.post(`/tools/email-headers`, { raw_headers: rawHeaders });
    return response.data;
  },
  toolsTyposquatting: async (domain: string) => {
    const response = await apiClient.get(`/tools/typosquatting`, { params: { domain } });
    return response.data;
  },
  toolsDecode: async (payload: string, decodeType: string = "auto") => {
    const response = await apiClient.post(`/tools/decode`, { payload, decode_type: decodeType });
    return response.data;
  },
  toolsDns: async (domain: string) => {
    const response = await apiClient.get(`/tools/dns`, { params: { domain } });
    return response.data;
  },
  toolsShodan: async (ip: string) => {
    const response = await apiClient.get(`/tools/shodan`, { params: { ip } });
    return response.data;
  },
  toolsMac: async (mac: string) => {
    const response = await apiClient.get(`/tools/mac`, { params: { mac } });
    return response.data;
  },
  toolsNetworkRange: async (cidr: string) => {
    const response = await apiClient.get(`/tools/network-range`, { params: { cidr } });
    return response.data;
  },
  toolsHttpHeaders: async (url: string) => {
    const response = await apiClient.get(`/tools/http-headers`, { params: { url } });
    return response.data;
  },
};
