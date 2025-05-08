export type LeadStatus = 'ok' | 'not_interested' | 'later' | 'not_connected';

export interface ScanResult {
  id: string;
  scanned_on: string;
  ip_address: string;
  url: string;
  vuln_high: number;
  vuln_medium: number;
  vuln_low: number;
  vuln_info: number;
  user_email: string;
  user_name: string;
  user_phone: string;
  status: LeadStatus;
  last_contact?: string;
  notes?: string;
}

export interface FilterOptions {
  dateRange: {
    start: string;
    end: string;
  };
  vulnerabilityLevel: 'all' | 'high' | 'medium' | 'low' | 'info';
  status: LeadStatus | 'all';
  search: string;
}