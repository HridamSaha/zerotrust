import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  Lock, 
  Unlock, 
  Zap, 
  CheckCircle, 
  XCircle, 
  BarChart3, 
  FileText, 
  RefreshCw, 
  Server, 
  Layers, 
  UserCheck, 
  Terminal,
  Crosshair,
  Sliders,
  LogOut,
  HelpCircle
} from 'lucide-react';
import { api } from './api';
import RiskGauge from './components/RiskGauge';

export default function App() {
  const [activeTab, setActiveTab] = useState('monitor'); // 'monitor' | 'simulator' | 'benchmark' | 'audit' | 'sessions'
  const [currentUser, setCurrentUser] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [selectedSessionUid, setSelectedSessionUid] = useState(null);
  const [currentSession, setCurrentSession] = useState(null);
  const [sessionEvents, setSessionEvents] = useState([]);
  const [riskHistory, setRiskHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pingResult, setPingResult] = useState(null);

  // Simulation state
  const [simAnomalyType, setSimAnomalyType] = useState('credential_stuffing');
  const [simEventCount, setSimEventCount] = useState(4);
  const [simRunning, setSimRunning] = useState(false);
  const [simResult, setSimResult] = useState(null);

  // Audit state
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditFilterAction, setAuditFilterAction] = useState('');
  const [selectedAuditEntry, setSelectedAuditEntry] = useState(null);

  // Init app with demo login
  useEffect(() => {
    initApp();
  }, []);

  const initApp = async (email = 'admin@zerotrust.demo', password = 'AdminDemo!234') => {
    setLoading(true);
    try {
      await api.login(email, password);
      const user = await api.getMe();
      setCurrentUser(user);
      await refreshSessions();
    } catch (err) {
      console.error('Init login failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const switchUser = async (roleType) => {
    if (roleType === 'admin') {
      await initApp('admin@zerotrust.demo', 'AdminDemo!234');
    } else {
      await initApp('user@zerotrust.demo', 'UserDemo!234');
    }
  };

  const refreshSessions = async () => {
    try {
      const res = await api.listSessions();
      setSessions(res.items || []);
      if (res.items && res.items.length > 0) {
        const targetUid = selectedSessionUid || res.items[0].session_uid;
        setSelectedSessionUid(targetUid);
        await loadSessionDetails(targetUid);
      }
    } catch (err) {
      console.error('Failed to load sessions:', err);
    }
  };

  const loadSessionDetails = async (uid) => {
    try {
      const sess = await api.getSession(uid);
      setCurrentSession(sess);

      const riskRes = await api.getSessionRisk(uid).catch(() => null);
      if (riskRes) {
        setRiskHistory(riskRes.history || []);
      }

      const eventsRes = await api.getSessionEvents(uid).catch(() => null);
      if (eventsRes) {
        setSessionEvents(eventsRes.items || []);
      }
    } catch (err) {
      console.error('Failed to load session details:', err);
    }
  };

  const handleSelectSession = (uid) => {
    setSelectedSessionUid(uid);
    setPingResult(null);
    loadSessionDetails(uid);
  };

  const handleCreateNewSession = async () => {
    setLoading(true);
    try {
      const created = await api.createSession('macbook-pro-m3', true, 'work_from_home');
      await refreshSessions();
      if (created.session) {
        handleSelectSession(created.session.session_uid);
      }
    } catch (err) {
      alert(`Error creating session: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeSession = async () => {
    if (!selectedSessionUid) return;
    try {
      await api.revokeSession(selectedSessionUid, 'Revoked manually via Operator Dashboard');
      await loadSessionDetails(selectedSessionUid);
      await refreshSessions();
    } catch (err) {
      alert(`Revoke failed: ${err.message}`);
    }
  };

  const handleTestProtectedPing = async () => {
    if (!selectedSessionUid) return;
    try {
      const res = await api.protectedPing(selectedSessionUid);
      setPingResult({ success: true, message: res.message, data: res });
    } catch (err) {
      setPingResult({ 
        success: false, 
        message: err.message, 
        status: err.status,
        revoked: err.status === 401 || err.status === 403 
      });
    }
  };

  const handleRunSimulation = async () => {
    if (!selectedSessionUid) return;
    setSimRunning(true);
    setSimResult(null);
    try {
      const res = await api.simulate(selectedSessionUid, simAnomalyType, simEventCount);
      setSimResult(res);
      await loadSessionDetails(selectedSessionUid);
      await refreshSessions();
    } catch (err) {
      alert(`Simulation error: ${err.message}`);
    } finally {
      setSimRunning(false);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const res = await api.getAuditLogs(1, 50, auditFilterAction || null);
      setAuditLogs(res.items || []);
    } catch (err) {
      console.error('Audit logs error:', err);
    }
  };

  useEffect(() => {
    if (activeTab === 'audit') {
      loadAuditLogs();
    }
  }, [activeTab, auditFilterAction]);

  const isAdmin = currentUser?.roles?.includes('admin');

  return (
    <div className="app-container">
      {/* Header */}
      <header className="app-header">
        <div className="brand-section">
          <div className="brand-icon">
            <Shield size={28} />
          </div>
          <div>
            <h1 className="brand-title">Zero-Trust Access Control Framework</h1>
            <p className="brand-subtitle">Continuous Risk Assessment & Adaptive Policy Enforcement</p>
          </div>
        </div>

        <div className="header-status-group">
          <div className="status-chip" title="FastAPI Backend Connected">
            <div className="status-dot pulsing" />
            <span>Backend: <strong>Live</strong></span>
          </div>

          <div className="status-chip" title="Active Model Architecture">
            <Layers size={14} color="#00f0ff" />
            <span>Model: <strong>Hybrid Stacking</strong></span>
          </div>

          {/* User Switcher */}
          <div className="user-badge" id="user-role-badge">
            <UserCheck size={16} color="#8b5cf6" />
            <span>{currentUser?.email || 'Authenticating...'}</span>
            <span className={`badge ${isAdmin ? 'badge-critical' : 'badge-low'}`}>
              {isAdmin ? 'ADMIN' : 'USER'}
            </span>
            <button 
              className="btn btn-secondary" 
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem', marginLeft: '0.5rem' }}
              onClick={() => switchUser(isAdmin ? 'user' : 'admin')}
              id="switch-user-btn"
            >
              Switch to {isAdmin ? 'User' : 'Admin'}
            </button>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="tabs-nav" id="main-navigation-tabs">
        <button
          className={`tab-btn ${activeTab === 'monitor' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitor')}
          id="tab-monitor-btn"
        >
          <Activity size={18} />
          Live Session Radar
        </button>
        <button
          className={`tab-btn ${activeTab === 'simulator' ? 'active' : ''}`}
          onClick={() => setActiveTab('simulator')}
          id="tab-simulator-btn"
        >
          <Crosshair size={18} />
          Attack & Anomaly Simulator
        </button>
        <button
          className={`tab-btn ${activeTab === 'benchmark' ? 'active' : ''}`}
          onClick={() => setActiveTab('benchmark')}
          id="tab-benchmark-btn"
        >
          <BarChart3 size={18} />
          ML Benchmark & Architecture
        </button>
        <button
          className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
          id="tab-audit-btn"
        >
          <FileText size={18} />
          Audit Vault & Compliance
        </button>
        <button
          className={`tab-btn ${activeTab === 'sessions' ? 'active' : ''}`}
          onClick={() => setActiveTab('sessions')}
          id="tab-sessions-btn"
        >
          <Sliders size={18} />
          All Sessions ({sessions.length})
        </button>
      </nav>

      {/* Main Content Area */}
      <main>
        {/* TAB 1: LIVE MONITOR */}
        {activeTab === 'monitor' && (
          <div className="grid-2">
            {/* Left Card: Session Risk Overview */}
            <div className="card" id="session-risk-overview-card">
              <div className="card-header">
                <h2 className="card-title">
                  <Shield size={20} color="#00f0ff" />
                  Session Continuous Risk Radar
                </h2>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button className="btn btn-secondary" onClick={() => loadSessionDetails(selectedSessionUid)} id="refresh-session-btn">
                    <RefreshCw size={14} /> Refresh
                  </button>
                  <button className="btn btn-primary" onClick={handleCreateNewSession} id="new-session-btn">
                    + New Session
                  </button>
                </div>
              </div>

              {currentSession ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <div>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>SESSION UID:</span>
                      <div className="mono" style={{ fontSize: '0.9rem', color: 'var(--cyan)' }}>
                        {currentSession.session_uid}
                      </div>
                    </div>
                    <div>
                      <span className={`badge badge-${currentSession.status}`}>
                        {currentSession.status.replace('_', ' ')}
                      </span>
                    </div>
                  </div>

                  {/* Animated Radial Risk Gauge */}
                  <RiskGauge 
                    score={currentSession.current_risk_score} 
                    level={currentSession.current_risk_level} 
                  />

                  {/* Quick Stat Badges */}
                  <div className="grid-3" style={{ marginTop: '1.5rem', marginBottom: '1.5rem' }}>
                    <div className="metric-card">
                      <span className="metric-label">Device Trust</span>
                      <span className="metric-value mono" style={{ fontSize: '1.2rem', color: currentSession.device_trusted ? 'var(--emerald)' : 'var(--crimson)' }}>
                        {currentSession.device_trusted ? 'TRUSTED' : 'UNVERIFIED'}
                      </span>
                      <span className="metric-sub">{currentSession.device_id || 'Unknown HW'}</span>
                    </div>

                    <div className="metric-card">
                      <span className="metric-label">Context Environment</span>
                      <span className="metric-value mono" style={{ fontSize: '1.2rem', color: 'var(--text-primary)' }}>
                        {currentSession.context_label || 'Standard'}
                      </span>
                      <span className="metric-sub">Client: {currentSession.client_ip || '127.0.0.1'}</span>
                    </div>

                    <div className="metric-card">
                      <span className="metric-label">Evaluated Events</span>
                      <span className="metric-value mono" style={{ fontSize: '1.2rem', color: 'var(--cyan)' }}>
                        {sessionEvents.length}
                      </span>
                      <span className="metric-sub">{riskHistory.length} assessments</span>
                    </div>
                  </div>

                  {/* Adaptive Enforcement Action Test */}
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: '1.2rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <h3 style={{ fontSize: '0.95rem', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Terminal size={16} color="#00f0ff" />
                      Zero-Trust Adaptive Invariant Enforcement Test
                    </h3>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                      Verify in real time that access decisions are strictly enforced. Revoked or high-risk sessions are immediately denied access to protected endpoints.
                    </p>

                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                      <button 
                        className="btn btn-primary" 
                        onClick={handleTestProtectedPing}
                        id="test-ping-btn"
                      >
                        <Lock size={15} /> Probe Protected Resource
                      </button>

                      {currentSession.status !== 'revoked' && (
                        <button 
                          className="btn btn-danger" 
                          onClick={handleRevokeSession}
                          id="revoke-session-btn"
                        >
                          <XCircle size={15} /> Immediate Session Revocation
                        </button>
                      )}
                    </div>

                    {/* Ping Feedback Banner */}
                    {pingResult && (
                      <div 
                        style={{ 
                          marginTop: '1rem', 
                          padding: '0.75rem 1rem', 
                          borderRadius: 'var(--radius-sm)',
                          backgroundColor: pingResult.success ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          border: `1px solid ${pingResult.success ? 'var(--emerald)' : 'var(--crimson)'}`,
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.75rem'
                        }}
                        id="ping-result-banner"
                      >
                        {pingResult.success ? <CheckCircle size={20} color="#10b981" /> : <XCircle size={20} color="#ef4444" />}
                        <div>
                          <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>
                            {pingResult.success ? 'Access Granted by Adaptive Policy Engine' : `Access Blocked: ${pingResult.message}`}
                          </div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            {pingResult.success 
                              ? 'Session token valid and continuous risk within allowable threshold.' 
                              : 'Zero-trust invariant triggered: session revoked or token invalidated.'}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading session data...
                </div>
              )}
            </div>

            {/* Right Card: Live Event Feed & Decision Stream */}
            <div className="card" id="event-feed-card">
              <div className="card-header">
                <h2 className="card-title">
                  <Activity size={20} color="#8b5cf6" />
                  Live Event Stream & Decision History
                </h2>
                <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Continuous Evaluation
                </span>
              </div>

              {riskHistory.length > 0 ? (
                <div className="timeline" id="risk-timeline-container">
                  {riskHistory.map((item, idx) => (
                    <div className="timeline-item" key={item.id || idx}>
                      <div style={{ paddingTop: '2px' }}>
                        {item.risk_level === 'critical' ? (
                          <AlertTriangle size={18} color="#ef4444" />
                        ) : item.risk_level === 'high' ? (
                          <AlertTriangle size={18} color="#f97316" />
                        ) : (
                          <CheckCircle size={18} color="#10b981" />
                        )}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span className="mono" style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                            Assessment #{item.id} — {item.model_name}
                          </span>
                          <span className={`badge badge-${item.risk_level}`}>
                            {item.risk_score?.toFixed(1)} / 100
                          </span>
                        </div>
                        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                          {item.explanation || `P(suspicious)=${item.probability?.toFixed(3)}`}
                        </p>
                        <div style={{ display: 'flex', gap: '1rem', marginTop: '0.4rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          <span>Latency: {item.inference_latency_ms?.toFixed(2)} ms</span>
                          <span>Time: {new Date(item.created_at).toLocaleTimeString()}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No risk evaluations recorded yet for this session. Use the Attack Simulator to inject activity.
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: ATTACK & ANOMALY SIMULATOR */}
        {activeTab === 'simulator' && (
          <div className="grid-2">
            {/* Left Card: Scenario Injection Controls */}
            <div className="card" id="attack-simulator-controls-card">
              <div className="card-header">
                <h2 className="card-title">
                  <Crosshair size={20} color="#f97316" />
                  Adversarial Anomaly & Attack Injection Console
                </h2>
              </div>

              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                Select an attack pattern to simulate continuous session risk escalation. The hybrid machine learning pipeline will process the sequence in real time and trigger adaptive access control responses.
              </p>

              <div className="preset-grid" id="attack-presets-container">
                {[
                  {
                    type: 'credential_stuffing',
                    name: 'Credential Stuffing',
                    desc: 'Repeated auth failures, foreign IP bursts, credential retries.',
                  },
                  {
                    type: 'privilege_escalation',
                    name: 'Privilege Escalation',
                    desc: 'Unauthorized probes on Level 5 sensitive resources (admin vault).',
                  },
                  {
                    type: 'burst_traffic',
                    name: 'Traffic Burst / DoS',
                    desc: 'High request frequency exceeding standard behavioral baseline.',
                  },
                  {
                    type: 'unusual_context',
                    name: 'Geo / Device Anomaly',
                    desc: 'Untrusted device fingerprint and unknown geographical context.',
                  },
                  {
                    type: 'benign',
                    name: 'Benign User Activity',
                    desc: 'Legitimate browsing and documentation viewing from trusted workstation.',
                  },
                ].map((preset) => (
                  <div
                    key={preset.type}
                    className={`preset-card ${simAnomalyType === preset.type ? 'selected' : ''}`}
                    onClick={() => setSimAnomalyType(preset.type)}
                    id={`preset-${preset.type}`}
                  >
                    <span className="preset-name">{preset.name}</span>
                    <span className="preset-desc">{preset.desc}</span>
                  </div>
                ))}
              </div>

              <div className="form-group">
                <label className="form-label">Number of Sequential Events ({simEventCount}):</label>
                <input
                  type="range"
                  min="1"
                  max="15"
                  value={simEventCount}
                  onChange={(e) => setSimEventCount(parseInt(e.target.value))}
                  style={{ width: '100%', accentColor: 'var(--cyan)' }}
                  id="event-count-slider"
                />
              </div>

              <div style={{ marginTop: '1.5rem' }}>
                <button
                  className="btn btn-primary"
                  style={{ width: '100%', padding: '0.85rem' }}
                  onClick={handleRunSimulation}
                  disabled={simRunning || !selectedSessionUid}
                  id="launch-simulation-btn"
                >
                  <Zap size={18} />
                  {simRunning ? 'Simulating Pipeline Ingestion...' : `Inject ${simEventCount} ${simAnomalyType.replace('_', ' ')} Events`}
                </button>
              </div>
            </div>

            {/* Right Card: Simulation Output & Reaction */}
            <div className="card" id="simulation-output-card">
              <div className="card-header">
                <h2 className="card-title">
                  <Terminal size={20} color="#00f0ff" />
                  Simulation Telemetry & Adaptive Response
                </h2>
              </div>

              {simResult ? (
                <div>
                  <div className="grid-3" style={{ marginBottom: '1.5rem' }}>
                    <div className="metric-card">
                      <span className="metric-label">Simulated Events</span>
                      <span className="metric-value mono" style={{ color: 'var(--cyan)' }}>
                        {simResult.events_simulated}
                      </span>
                    </div>

                    <div className="metric-card">
                      <span className="metric-label">Final Risk Score</span>
                      <span className="metric-value mono" style={{ color: simResult.final_risk_score > 50 ? 'var(--crimson)' : 'var(--emerald)' }}>
                        {simResult.final_risk_score.toFixed(1)}
                      </span>
                    </div>

                    <div className="metric-card">
                      <span className="metric-label">Final Status</span>
                      <span className={`badge badge-${simResult.final_status}`} style={{ alignSelf: 'flex-start', marginTop: '0.4rem' }}>
                        {simResult.final_status}
                      </span>
                    </div>
                  </div>

                  <h3 style={{ fontSize: '0.9rem', marginBottom: '0.75rem', color: 'var(--text-muted)' }}>
                    PER-EVENT ADAPTIVE DECISION SEQUENCE:
                  </h3>

                  <div className="table-container" style={{ maxHeight: '350px' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Event</th>
                          <th>Score</th>
                          <th>Level</th>
                          <th>Policy Decision</th>
                          <th>Latency</th>
                        </tr>
                      </thead>
                      <tbody>
                        {simResult.assessments.map((a, i) => (
                          <tr key={i}>
                            <td className="mono">#{i + 1}</td>
                            <td className="mono" style={{ fontWeight: 700 }}>
                              {a.risk_score.toFixed(1)}
                            </td>
                            <td>
                              <span className={`badge badge-${a.risk_level}`}>
                                {a.risk_level}
                              </span>
                            </td>
                            <td>
                              <span className={`decision-pill decision-${a.decision}`}>
                                {a.decision}
                              </span>
                            </td>
                            <td className="mono" style={{ fontSize: '0.75rem' }}>
                              {a.inference_latency_ms?.toFixed(2)}ms
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div style={{ padding: '4rem 2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Crosshair size={36} color="var(--border-subtle)" style={{ marginBottom: '1rem' }} />
                  <p>No active simulation run. Select an attack scenario on the left and click "Inject Events".</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 3: ML BENCHMARK & ARCHITECTURE */}
        {activeTab === 'benchmark' && (
          <div>
            <div className="card" style={{ marginBottom: '1.5rem' }} id="benchmark-comparison-card">
              <div className="card-header">
                <h2 className="card-title">
                  <BarChart3 size={20} color="#00f0ff" />
                  Comparative Model Performance (Held-out Test Evaluation)
                </h2>
                <span className="badge badge-low">PHASE 5 & 6 BENCHMARK</span>
              </div>

              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Architecture</th>
                      <th>Model Paradigm</th>
                      <th>PR-AUC (Primary)</th>
                      <th>F1-Score</th>
                      <th>Recall</th>
                      <th>Precision</th>
                      <th>ROC-AUC</th>
                      <th>Inference Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style={{ fontWeight: 700 }}>Model A: Rule Baseline</td>
                      <td>Static Heuristic Rules</td>
                      <td className="mono">0.110</td>
                      <td className="mono">0.198</td>
                      <td className="mono">0.800</td>
                      <td className="mono">0.113</td>
                      <td className="mono">0.979</td>
                      <td className="mono" style={{ color: 'var(--emerald)' }}>~0.001 ms</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 700 }}>Model B: LightGBM</td>
                      <td>Gradient Boosted Trees (Tabular)</td>
                      <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 700 }}>0.235</td>
                      <td className="mono">0.270</td>
                      <td className="mono">0.500</td>
                      <td className="mono">0.185</td>
                      <td className="mono">0.880</td>
                      <td className="mono" style={{ color: 'var(--emerald)' }}>0.004 ms</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 700 }}>Model C: GRU Sequence</td>
                      <td>Recurrent Neural Network (PyTorch)</td>
                      <td className="mono" style={{ color: 'var(--purple)', fontWeight: 700 }}>0.433</td>
                      <td className="mono">0.235</td>
                      <td className="mono" style={{ color: 'var(--emerald)' }}>0.800</td>
                      <td className="mono">0.138</td>
                      <td className="mono">0.973</td>
                      <td className="mono">0.108 ms</td>
                    </tr>
                    <tr style={{ background: 'rgba(0, 240, 255, 0.05)' }}>
                      <td style={{ fontWeight: 800, color: 'var(--cyan)' }}>Model D: Hybrid Fusion</td>
                      <td>Logistic Stacking + Sequential Blend</td>
                      <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 800 }}>Ensemble Stacking</td>
                      <td className="mono">Adaptive</td>
                      <td className="mono">High Sensitivity</td>
                      <td className="mono">Calibrated</td>
                      <td className="mono">Robust</td>
                      <td className="mono" style={{ color: 'var(--emerald)' }}>&lt; 1.5 ms</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Architectural Principles Grid */}
            <div className="grid-3">
              <div className="card">
                <h3 className="card-title" style={{ fontSize: '1rem', marginBottom: '0.75rem', color: 'var(--cyan)' }}>
                  1. Feature Engineering
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  17 tabular features (failed login ratio, burst score, sensitivity mean/max, off-hours, context deviation) and 10 normalized sequence feature channels fed to GRU sliding windows.
                </p>
              </div>

              <div className="card">
                <h3 className="card-title" style={{ fontSize: '1rem', marginBottom: '0.75rem', color: 'var(--purple)' }}>
                  2. Hysteresis & Damping
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  Prevents policy decision flapping on boundary risk fluctuations. Downward transitions require consistent benign events before restoring relaxed permissions.
                </p>
              </div>

              <div className="card">
                <h3 className="card-title" style={{ fontSize: '1rem', marginBottom: '0.75rem', color: 'var(--emerald)' }}>
                  3. Zero-Trust Invariant
                </h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  RBAC acts as a non-negotiable security boundary: non-admins cannot access admin resources regardless of risk score. Revoked sessions immediately invalidate JWT session tokens.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: AUDIT VAULT & COMPLIANCE */}
        {activeTab === 'audit' && (
          <div className="card" id="audit-logs-card">
            <div className="card-header">
              <h2 className="card-title">
                <FileText size={20} color="#00f0ff" />
                Immutable Audit Trail & Compliance Vault
              </h2>
              <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                <select 
                  className="form-select" 
                  value={auditFilterAction}
                  onChange={(e) => setAuditFilterAction(e.target.value)}
                  style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
                  id="audit-filter-action"
                >
                  <option value="">All Actions</option>
                  <option value="risk_assessment">Risk Assessments</option>
                  <option value="session_revoke">Revocations</option>
                  <option value="auth_login">Logins</option>
                </select>
                <button className="btn btn-secondary" onClick={loadAuditLogs} id="refresh-audit-btn">
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>
            </div>

            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Log ID</th>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Outcome</th>
                    <th>Evidence / Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.length > 0 ? (
                    auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td className="mono">#{log.id}</td>
                        <td className="mono" style={{ fontSize: '0.75rem' }}>
                          {new Date(log.created_at).toLocaleString()}
                        </td>
                        <td style={{ fontWeight: 600 }}>{log.action}</td>
                        <td className="mono" style={{ color: 'var(--text-muted)' }}>
                          {log.resource || '—'}
                        </td>
                        <td>
                          <span className={`badge ${log.outcome === 'allow' ? 'badge-low' : log.outcome === 'revoke' || log.outcome === 'revoked' ? 'badge-critical' : 'badge-medium'}`}>
                            {log.outcome}
                          </span>
                        </td>
                        <td>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '0.2rem 0.6rem', fontSize: '0.75rem' }}
                            onClick={() => setSelectedAuditEntry(log)}
                          >
                            Inspect Detail
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="6" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                        No audit log entries matching criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Audit Detail Modal */}
            {selectedAuditEntry && (
              <div 
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0,0,0,0.7)',
                  backdropFilter: 'blur(8px)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 999
                }}
                onClick={() => setSelectedAuditEntry(null)}
              >
                <div 
                  className="card" 
                  style={{ width: '600px', maxWidth: '90%', maxHeight: '80vh', overflowY: 'auto' }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="card-header">
                    <h3 className="card-title">Audit Record #{selectedAuditEntry.id}</h3>
                    <button className="btn btn-secondary" onClick={() => setSelectedAuditEntry(null)}>Close</button>
                  </div>
                  <pre className="mono" style={{ background: '#05070a', padding: '1rem', borderRadius: 'var(--radius-sm)', fontSize: '0.8rem', overflowX: 'auto', color: 'var(--cyan)' }}>
                    {JSON.stringify(selectedAuditEntry, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 5: ALL SESSIONS EXPLORER */}
        {activeTab === 'sessions' && (
          <div className="card" id="all-sessions-card">
            <div className="card-header">
              <h2 className="card-title">
                <Sliders size={20} color="#00f0ff" />
                Active Sessions Registry ({sessions.length})
              </h2>
              <button className="btn btn-primary" onClick={handleCreateNewSession}>
                + Create Session
              </button>
            </div>

            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Session UID</th>
                    <th>Status</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Device</th>
                    <th>Created At</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr 
                      key={s.id} 
                      style={{ background: s.session_uid === selectedSessionUid ? 'rgba(0, 240, 255, 0.05)' : 'transparent' }}
                    >
                      <td className="mono" style={{ color: 'var(--cyan)', fontWeight: 600 }}>
                        {s.session_uid}
                      </td>
                      <td>
                        <span className={`badge badge-${s.status}`}>
                          {s.status}
                        </span>
                      </td>
                      <td className="mono" style={{ fontWeight: 700 }}>
                        {s.current_risk_score.toFixed(1)}
                      </td>
                      <td>
                        <span className={`badge badge-${s.current_risk_level}`}>
                          {s.current_risk_level}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8rem' }}>
                        {s.device_id || 'Browser'} ({s.device_trusted ? 'Trusted' : 'Untrusted'})
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem' }}>
                        {new Date(s.created_at).toLocaleTimeString()}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem' }}
                          onClick={() => {
                            handleSelectSession(s.session_uid);
                            setActiveTab('monitor');
                          }}
                        >
                          Select & Monitor
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
