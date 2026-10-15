/**
 * Zero-Trust Framework Frontend API Client
 */

const API_BASE = '/api';

class ApiClient {
  constructor() {
    this.token = localStorage.getItem('zt_token') || null;
  }

  setToken(token) {
    this.token = token;
    if (token) {
      localStorage.setItem('zt_token', token);
    } else {
      localStorage.removeItem('zt_token');
    }
  }

  async request(endpoint, options = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const errorMsg = data.detail || `HTTP Error ${response.status}`;
      const err = new Error(errorMsg);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return data;
  }

  // Auth
  async login(email, password, device_id = 'demo-device-01', device_trusted = true, context_label = 'lab_workstation') {
    const res = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, device_id, device_trusted, context_label }),
    });
    if (res.access_token) {
      this.setToken(res.access_token);
    }
    return res;
  }

  async getMe() {
    return this.request('/auth/me');
  }

  async getHealth() {
    return this.request('/health');
  }

  // Sessions
  async listSessions() {
    return this.request('/sessions');
  }

  async createSession(deviceId = 'device-workstation', deviceTrusted = true, contextLabel = 'secure_office') {
    return this.request('/sessions', {
      method: 'POST',
      body: JSON.stringify({ device_id: deviceId, device_trusted: deviceTrusted, context_label: contextLabel }),
    });
  }

  async getSession(sessionUid) {
    return this.request(`/sessions/${sessionUid}`);
  }

  async postEvent(sessionUid, eventPayload) {
    return this.request(`/sessions/${sessionUid}/events`, {
      method: 'POST',
      body: JSON.stringify(eventPayload),
    });
  }

  async getSessionRisk(sessionUid) {
    return this.request(`/sessions/${sessionUid}/risk`);
  }

  async getSessionEvents(sessionUid) {
    return this.request(`/sessions/${sessionUid}/events`);
  }

  async revokeSession(sessionUid, reason = 'Operator triggered revocation') {
    return this.request(`/sessions/${sessionUid}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async protectedPing(sessionUid) {
    return this.request(`/sessions/${sessionUid}/protected-ping`);
  }

  // Simulation
  async simulate(sessionUid, anomalyType = 'burst_traffic', eventCount = 5) {
    return this.request('/sessions/simulate', {
      method: 'POST',
      body: JSON.stringify({
        session_uid: sessionUid,
        anomaly_type: anomalyType,
        event_count: eventCount,
      }),
    });
  }

  // Admin & Audit
  async getAdminOverview() {
    return this.request('/admin/sessions/overview');
  }

  async getAuditLogs(page = 1, pageSize = 50, action = null, outcome = null) {
    let url = `/audit-logs?page=${page}&page_size=${pageSize}`;
    if (action) url += `&action=${encodeURIComponent(action)}`;
    if (outcome) url += `&outcome=${encodeURIComponent(outcome)}`;
    return this.request(url);
  }
}

export const api = new ApiClient();
