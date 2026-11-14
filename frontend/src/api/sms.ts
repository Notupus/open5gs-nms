import axios from 'axios';

const api = axios.create({ baseURL: '/api/sms', withCredentials: true });

export interface SmsStatus {
  installed: boolean;
  services: { stp: boolean; hlr: boolean; msc: boolean };
  hlrSubscribers: number;
  open5gsSubscribers: number;
  mmeSgsConfigured: boolean;
  smsEnabled: boolean;
  hasSavedConfig: boolean;
  currentConfig?: { mscBindIp: string; hlrBindIp: string; mmeLocalIp: string };
}

export interface SmsConfigureInput {
  mscBindIp:  string;
  hlrBindIp:  string;
  mmeLocalIp: string;
}

export interface SmsConfigFile {
  path: string; label: string; group: string; language: string;
  restartServices: string[]; exists: boolean;
}

export interface SmsCdrRecord {
  id: number;
  created_at: string;
  direction: 'MO' | 'MT' | string;
  sender: string;
  recipient: string;
  dcs: number;
  text: string;
  status: 'DELIVERED' | 'QUEUED' | 'FAILED' | string;
}

export interface SmsQueueItem {
  id: number;
  caller: string;
  callee: string;
  text: string;
  dcs: number;
  valid: string;
}

export interface SmsInspectorData {
  success: boolean;
  records: SmsCdrRecord[];
  queue: SmsQueueItem[];
  stats: {
    cumulativeSmsTotal: number;
    processLifetimeSmsTotal: number;
    queueDepth: number;
    totalCdr: number;
  };
}

export const smsApi = {
  getStatus:       async (): Promise<SmsStatus> => { const { data } = await api.get('/status'); return data; },
  configure:       async (input: SmsConfigureInput) => { const { data } = await api.post('/configure', input); return data; },
  syncSubscribers: async () => { const { data } = await api.post('/sync-subscribers'); return data; },
  sendTest:        async (to: string, from: string, text: string): Promise<{ success: boolean; output?: string; error?: string }> => {
    const { data } = await api.post('/send-test', { to, from, text }); return data;
  },
  enable:          async () => { const { data } = await api.post('/enable'); return data; },
  disable:         async () => { const { data } = await api.post('/disable'); return data; },
  start:           async () => { const { data } = await api.post('/start'); return data; },
  stop:            async () => { const { data } = await api.post('/stop'); return data; },
  restart:         async () => { const { data } = await api.post('/restart'); return data; },
  install:         () => fetch('/api/sms/install', { method: 'POST', credentials: 'include' }),
  uninstall:       () => fetch('/api/sms/uninstall', { method: 'POST', credentials: 'include' }),
  getConfigs:        async (): Promise<{ files: SmsConfigFile[] }> => { const { data } = await api.get('/configs'); return data; },
  getConfigContent:  async (filePath: string): Promise<{ content: string; exists: boolean }> => {
    const { data } = await api.get('/configs/content', { params: { path: filePath } }); return data;
  },
  saveConfigContent: async (filePath: string, content: string): Promise<{ success: boolean }> => {
    const { data } = await api.put('/configs/content', { path: filePath, content }); return data;
  },
  restartServices:   async (services: string[]): Promise<{ success: boolean; results: string[] }> => {
    const { data } = await api.post('/configs/restart', { services }); return data;
  },
  getInspector: async (): Promise<SmsInspectorData> => {
    const { data } = await api.get('/inspector'); return data;
  },
  resetCounter: async (): Promise<{ success: boolean; message?: string; error?: string }> => {
    const { data } = await api.post('/inspector/reset-counter'); return data;
  },
  clearQueue: async (): Promise<{ success: boolean; message?: string; error?: string }> => {
    const { data } = await api.post('/inspector/clear-queue'); return data;
  },
};
