/**
 * ML Backend API Service
 * Communicates with the Python FastAPI backend for ML model predictions
 */

// Dynamically use the current page's hostname so it works from any device on the network
const _host = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
const ML_API_BASE_URL = (import.meta.env.VITE_ML_API_URL as string) || `http://${_host}:8000/api`;
const WS_BASE_URL = ML_API_BASE_URL.replace(/\/api$/, '').replace(/^http/, 'ws');

interface RiskScorePayload {
  user_id: string;
  behavior_metrics: {
    normal_login_time: number;
    actual_login_time: number;
    normal_session_duration: number;
    actual_session_duration: number;
    normal_data_volume: number;
    actual_data_volume: number;
    normal_api_calls: number;
    actual_api_calls: number;
    normal_geo_distance: number;
    actual_geo_distance: number;
  };
  anomaly_score: number;
}

interface RiskScoreResponse {
  overall_score: number;
  threat_level: "safe" | "low" | "medium" | "high" | "critical";
  deviations: Record<string, number>;
  recommendation: string;
}

interface AnomalyRecord {
  [key: string]: number | boolean | string;
  is_anomaly: boolean;
  anomaly_score: number;
  risk_level: string;
}

interface PropagationNode {
  id: string;
  label: string;
  type: string;
  x: number;
  y: number;
  compromised: boolean;
  propagationRisk: number;
}

interface PropagationEdge {
  from: string;
  to: string;
  active: boolean;
  attackPath: boolean;
}

class MLBackendService {
  private baseUrl: string;
  private ws: WebSocket | null = null;
  private wsListeners: Array<(data: any) => void> = [];
  private wsReconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    this.baseUrl = ML_API_BASE_URL;
  }

  // ── WebSocket for instant threat push ──

  connectWebSocket(): void {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return; // Already connected
    }

    const wsUrl = `${WS_BASE_URL}/ws/admin`;
    console.log(`[WS] Connecting to ${wsUrl}`);
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      console.log('[WS] Connected — dashboard will receive instant threat events');
      // Keep alive ping every 30s
      const ping = setInterval(() => {
        if (this.ws?.readyState === WebSocket.OPEN) {
          this.ws.send('ping');
        } else {
          clearInterval(ping);
        }
      }, 30000);
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'pong') return; // heartbeat reply
        // Notify all listeners
        this.wsListeners.forEach(fn => fn(data));
      } catch { /* ignore parse errors */ }
    };

    this.ws.onclose = () => {
      console.log('[WS] Disconnected — reconnecting in 3s');
      this.ws = null;
      this.wsReconnectTimer = setTimeout(() => this.connectWebSocket(), 3000);
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  onThreatEvent(callback: (data: any) => void): () => void {
    this.wsListeners.push(callback);
    // Return unsubscribe function
    return () => {
      this.wsListeners = this.wsListeners.filter(fn => fn !== callback);
    };
  }

  disconnectWebSocket(): void {
    if (this.wsReconnectTimer) clearTimeout(this.wsReconnectTimer);
    this.ws?.close();
    this.ws = null;
  }

  /**
   * Health check endpoint
   */
  async healthCheck(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/health`);
      if (!response.ok) throw new Error("Backend health check failed");
      return await response.json();
    } catch (error) {
      console.error("Health check error:", error);
      throw error;
    }
  }

  /**
   * Calculate risk score for a user
   */
  async calculateRiskScore(payload: RiskScorePayload): Promise<RiskScoreResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/risk-score`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Risk score calculation failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Risk score calculation error:", error);
      throw error;
    }
  }

  /**
   * Detect anomalies in behavioral records
   */
  async detectAnomalies(records: Record<string, number>[]): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/anomaly-detection`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ records }),
      });

      if (!response.ok) {
        throw new Error(`Anomaly detection failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Anomaly detection error:", error);
      throw error;
    }
  }

  /**
   * Analyze network propagation risks
   */
  async analyzePropagation(
    nodes: PropagationNode[],
    edges: PropagationEdge[]
  ): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/propagation-analysis`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ nodes, edges }),
      });

      if (!response.ok) {
        throw new Error(`Propagation analysis failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Propagation analysis error:", error);
      throw error;
    }
  }

  /**
   * Train the anomaly detector with historical data
   */
  async trainAnomalyDetector(data: number[][], features: string[]): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/train-anomaly-detector`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ data, features }),
      });

      if (!response.ok) {
        throw new Error(`Model training failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Training error:", error);
      throw error;
    }
  }

  /**
   * Batch risk analysis for multiple users
   */
  async batchRiskAnalysis(usersData: any[]): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/batch-risk-analysis`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(usersData),
      });

      if (!response.ok) {
        throw new Error(`Batch analysis failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Batch analysis error:", error);
      throw error;
    }
  }

  /**
   * Check if backend is available
   */
  async isBackendAvailable(): Promise<boolean> {
    try {
      await this.healthCheck();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Poll live threat feed (for real-time attack demo)
   */
  async getLiveThreat(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/live-threat`);
      if (!response.ok) throw new Error("Failed to fetch live threat");
      return await response.json();
    } catch (error) {
      return null;
    }
  }

  /**
   * Reset live threat state
   */
  async resetLiveThreat(): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/live-threat/reset`, { method: "POST" });
    } catch {
      // ignore
    }
  }

  /**
   * Real login — sends device fingerprint to backend.
   * Backend does GeoIP, baseline comparison, ML analysis, and pushes result via WS.
   */
  async login(username: string, password: string, fingerprint: any, fingerprintId?: string): Promise<any> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      const response = await fetch(`${this.baseUrl}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, fingerprint, fingerprint_id: fingerprintId }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!response.ok) throw new Error(`Login detection failed: ${response.statusText}`);
      return await response.json();
    } catch (error: any) {
      if (error.name === 'AbortError') {
        console.error("Login request timed out");
        throw new Error('Login request timed out. Please try again.');
      }
      console.error("Login detection error:", error);
      throw error;
    }
  }

  /**
   * Get stored baselines for admin view
   */
  async getBaselines(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/baselines`);
      if (!response.ok) throw new Error('Failed to fetch baselines');
      return await response.json();
    } catch (error) {
      console.error('Baselines fetch error:', error);
      return { baselines: {}, count: 0 };
    }
  }

  /**
   * Reset baselines
   */
  async resetBaselines(username?: string): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/baselines/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(username ? { username } : {}),
      });
    } catch { /* ignore */ }
  }

  // ── Attack Chain Simulation ──

  async startAttackChain(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/attack-chain/start`, { method: "POST" });
      if (!response.ok) throw new Error("Failed to start attack chain");
      return await response.json();
    } catch (error) {
      console.error("Attack chain start error:", error);
      throw error;
    }
  }

  async stopAttackChain(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/attack-chain/stop`, { method: "POST" });
      if (!response.ok) throw new Error("Failed to stop attack chain");
      return await response.json();
    } catch (error) {
      console.error("Attack chain stop error:", error);
      throw error;
    }
  }

  async getAttackChainStatus(): Promise<{ running: boolean }> {
    try {
      const response = await fetch(`${this.baseUrl}/attack-chain/status`);
      if (!response.ok) return { running: false };
      return await response.json();
    } catch {
      return { running: false };
    }
  }
}

export const mlBackendService = new MLBackendService();

export type {
  RiskScorePayload,
  RiskScoreResponse,
  AnomalyRecord,
  PropagationNode,
  PropagationEdge,
};
