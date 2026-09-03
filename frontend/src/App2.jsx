import React, { useState, useEffect, useRef, useCallback } from 'react';
import ReactDOM from 'react-dom';

const BASE = '/api';
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SEVERITY_COLORS = { critical: '#ff0000', high: '#ff1744', medium: '#ff9100', low: '#ffab00' };
const SEVERITY_BADGE = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
const ALERT_TYPES = ['All', 'File', 'Network', 'Process', 'Identity', 'Behavior'];
const ALERT_STATUSES = ['All', 'Open', 'Acknowledged', 'Resolved', 'Dismissed'];
const AGENT_STATUSES = ['All', 'Online', 'Offline', 'Compromised', 'Updating'];

const InvestSection = ({ title, sectionKey, expanded, onToggle, children, defaultOpen }) => {
  const isOpen = expanded[sectionKey] === undefined ? !!defaultOpen : expanded[sectionKey];
  return (
    <div className="invest-section" style={{ borderBottom: '1px solid var(--border)' }}>
      <div className="invest-header" onClick={() => onToggle(sectionKey)} style={{ borderLeft: isOpen ? '3px solid var(--primary)' : '3px solid transparent' }}>
        <span className="invest-title">{title}</span>
        <span className={`invest-chevron ${isOpen ? 'open' : ''}`}>&#x25BC;</span>
      </div>
      {isOpen && <div className="invest-body">{children}</div>}
    </div>
  );
};

const InfoRow = ({ label, value, mono }) => (
  <div className="info-row" style={{ display: 'flex', gap: '6px', alignItems: 'baseline' }}>
    <span className="info-label" style={{ minWidth: '80px', flexShrink: 0 }}>{label}</span>
    {typeof value === 'string' ? (
      <span className={mono ? 'mono' : ''} style={{ color: 'var(--text1)', fontSize: '12px', wordBreak: 'break-all' }}>{value}</span>
    ) : <span>{value}</span>}
  </div>
);

const MITRE_TACTICS = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command & Control', 'Exfiltration', 'Impact'];
const MITRE_TECHNIQUES = [
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access' },
  { id: 'T1059', name: 'Command & Scripting Interpreter', tactic: 'Execution' },
  { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
  { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'Persistence' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' },
  { id: 'T1046', name: 'Network Service Scanning', tactic: 'Discovery' },
  { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command & Control' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration' },
  { id: 'T1485', name: 'Data Destruction', tactic: 'Impact' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion' },
  { id: 'T1518', name: 'Software Discovery', tactic: 'Discovery' },
  { id: 'T1090', name: 'Proxy', tactic: 'Command & Control' },
  { id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'Credential Access' },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Execution' },
  { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' },
  { id: 'T1550', name: 'Use Alternate Authentication Material', tactic: 'Lateral Movement' },
  { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' },
  { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'Impact' },
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
  { id: 'T1583', name: 'Acquire Infrastructure', tactic: 'Resource Development' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
  { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
  { id: 'T1070', name: 'Indicator Removal', tactic: 'Defense Evasion' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery' },
  { id: 'T1057', name: 'Process Discovery', tactic: 'Discovery' },
  { id: 'T1005', name: 'Data from Local System', tactic: 'Collection' },
  { id: 'T1074', name: 'Data Staged', tactic: 'Collection' },
  { id: 'T1560', name: 'Archive Collected Data', tactic: 'Collection' },
  { id: 'T1537', name: 'Transfer Data to Cloud Account', tactic: 'Exfiltration' },
  { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
  { id: 'T1519', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery' },
];

const NAV = [
  { path: '/', label: 'Dashboard', icon: '\u{1F4CA}' },
  { path: '/agents', label: 'Agents', icon: '\u{1F5A5}\uFE0F' },
  { path: '/alerts', label: 'Alerts', icon: '\u{1F6A8}' },
  { path: '/threats', label: 'Threat Map', icon: '\u{1F5FA}\uFE0F' },
  { path: '/settings', label: 'Settings', icon: '\u2699\uFE0F' },
  { path: '/mitre', label: 'MITRE ATT&CK', icon: '\u{1F52C}' },
];

function randomId() { return Math.random().toString(36).substring(2, 10); }

function getAuthToken() { return localStorage.getItem('access_token'); }
function setAuthToken(t) { if (t) localStorage.setItem('access_token', t); else localStorage.removeItem('access_token'); }
function getAuthHeaders() {
  const t = getAuthToken();
  return t ? { 'Authorization': `Bearer ${t}` } : {};
}

function apiFetch(path, opts = {}) {
  return fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders(), ...opts.headers },
    ...opts,
  }).then(r => {
    if (r.status === 401) { setAuthToken(null); window.location.reload(); }
    if (!r.ok) return r.json().then(body => { const e = new Error(body.detail || `API error ${r.status}`); e.status = r.status; throw e; });
    return r.json().catch(() => ({}));
  });
}

function AuthPage({ onAuth, theme, toggleTheme }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('login');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPass, setShowPass] = useState(false);

  // 3D Parallax Tilt state
  const [tilt, setTilt] = useState({ x: 0, y: 0 });
  const [glowPos, setGlowPos] = useState({ x: 50, y: 50 });
  const cardRef = useRef(null);

  const handleMouseMove = (e) => {
    if (!cardRef.current) return;
    const card = cardRef.current;
    const rect = card.getBoundingClientRect();

    // Mouse coords relative to card
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    // Mouse coords centered around 0
    const centerX = x - rect.width / 2;
    const centerY = y - rect.height / 2;

    // 3D rotations (max tilt ~12 degrees)
    const rotateX = (centerY / (rect.height / 2)) * -12;
    const rotateY = (centerX / (rect.width / 2)) * 12;

    setTilt({ x: rotateX, y: rotateY });

    // Glow position (percentage)
    const glowX = (x / rect.width) * 100;
    const glowY = (y / rect.height) * 100;
    setGlowPos({ x: glowX, y: glowY });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 0, y: 0 });
    setGlowPos({ x: 50, y: 50 });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const endpoint = mode === 'login' ? '/auth/login' : '/auth/register';
      const data = await apiFetch(endpoint, { method: 'POST', body: JSON.stringify({ email, password }) });
      setAuthToken(data.access_token);
      onAuth(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page" style={{ perspective: '1000px' }}>
      {/* Theme Toggle Button */}
      <button
        onClick={toggleTheme}
        className="theme-toggle"
        title="Toggle Light/Dark Theme"
        style={{
          position: 'absolute',
          top: '24px',
          right: '24px',
          background: 'rgba(255,255,255,0.05)',
          border: '1px solid var(--border3)',
          borderRadius: '8px',
          cursor: 'pointer',
          fontSize: '18px',
          width: '36px',
          height: '36px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
          transition: 'all 0.2s ease',
          color: 'var(--text)'
        }}
        onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.1)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)'; }}
      >
        {theme === 'dark' ? '☀️' : '🌙'}
      </button>

      {/* Left Branding Panel */}
      <div className="auth-brand">
        <div className="auth-hex-grid" />

        {/* Floating security badges */}
        <div className="auth-float-badge">
          <span className="badge-dot green" />AES-256 Encrypted
        </div>
        <div className="auth-float-badge">
          <span className="badge-dot violet" />MITRE ATT&CK Ready
        </div>
        <div className="auth-float-badge">
          <span className="badge-dot cyan" />Real-time Monitoring
        </div>
        <div className="auth-float-badge">
          <span className="badge-dot green" />Zero-Trust Architecture
        </div>

        <div className="auth-brand-content" style={{ transform: 'translateZ(40px)' }}>
          <div className="auth-logo" style={{ textShadow: '0 0 20px rgba(245,158,11,0.35)' }}>SPECTRA SHIELD</div>
          <div className="auth-subtitle">EDR / XDR Platform</div>
          <div className="auth-tagline">
            Defend. <span>Detect.</span> Dominate.
          </div>
        </div>
      </div>

      {/* Right Form Panel */}
      <div className="auth-form-panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div
          ref={cardRef}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
          className="auth-form-card"
          style={{
            transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg) translateZ(10px)`,
            transition: 'transform 0.08s ease-out, box-shadow 0.15s ease',
            transformStyle: 'preserve-3d',
            boxShadow: `0 30px 70px rgba(0,0,0,0.65), 0 0 0 1px rgba(245,158,11,0.14), 0 0 60px rgba(245,158,11,0.08)`,
            position: 'relative'
          }}
        >
          {/* Inner Light Follow Glow */}
          <div style={{
            position: 'absolute',
            inset: 0,
            pointerEvents: 'none',
            background: `radial-gradient(circle 180px at ${glowPos.x}% ${glowPos.y}%, rgba(245,158,11,0.16) 0%, transparent 80%)`,
            zIndex: 1,
            borderRadius: 'inherit',
            transition: 'background 0.05s ease-out'
          }} />

          {/* Floating UI layers using translateZ */}
          <div style={{ transform: 'translateZ(30px)', transformStyle: 'preserve-3d' }}>
            <div className="auth-form-title">
              {mode === 'login' ? 'Welcome Back' : 'Create Account'}
            </div>
            <div className="auth-form-subtitle">
              {mode === 'login'
                ? 'Sign in to your security dashboard'
                : 'Set up your secure credentials'}
            </div>
          </div>

          <form onSubmit={handleSubmit} style={{ transform: 'translateZ(20px)', transformStyle: 'preserve-3d' }}>
            <div className="auth-input-group">
              <label>Email Address</label>
              <div className="auth-input-wrap">
                <span className="auth-input-icon">&#x2709;</span>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  placeholder="agent@spectra.io"
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="auth-input-group" style={{ marginBottom: '24px' }}>
              <label>Password</label>
              <div className="auth-input-wrap">
                <span className="auth-input-icon">&#x1F512;</span>
                <input
                  type={showPass ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  placeholder={mode === 'login' ? 'Enter your password' : 'At least 8 characters'}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                />
                <button
                  type="button"
                  className="auth-pass-toggle"
                  onClick={() => setShowPass(p => !p)}
                  tabIndex={-1}
                >
                  {showPass ? '\u{1F441}' : '\u{1F441}\u200D\u{1F5E8}'}
                </button>
              </div>
            </div>

            {error && <div className="auth-error">{error}</div>}

            <button type="submit" className="auth-submit" disabled={loading} style={{ transform: 'translateZ(35px)' }}>
              {loading
                ? (mode === 'login' ? 'Authenticating...' : 'Creating Account...')
                : (mode === 'login' ? 'Sign In \u2192' : 'Create Account \u2192')}
            </button>
          </form>

          <div className="auth-switch" style={{ transform: 'translateZ(15px)' }}>
            <button onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); }}>
              {mode === 'login' ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function normalizeAgent(a) {
  if (!a) return a;
  return {
    ...a,
    name: a.hostname,
    os: a.os_type,
    ip: a.ip_address,
    cpu: a.cpu_usage ?? 0,
    ram: a.ram_total_gb ? Math.min(Math.round(((a.ram_used_gb || 0) / a.ram_total_gb) * 100), 100) : 0,
    lastSeen: a.last_heartbeat,
  };
}

function normalizeAlert(a) {
  if (!a) return a;
  return {
    ...a,
    timestamp: a.created_at,
    agentName: a.agent_hostname,
    mitreTactic: a.mitre_tactic_name || a.mitreTactic,
    mitreTechnique: a.mitre_technique_name || a.mitreTechnique,
    mitreTechniqueId: a.mitre_technique_id,
    hostname: a.agent_hostname,
    firstSeen: a.created_at,
    description: a.description || a.title,
    techniqueId: a.mitre_technique_id,
    technique: a.mitre_technique_name,
  };
}

// ---- SIDEBAR ----
function Sidebar({ page, navigate, connected, userEmail, onLogout, theme, toggleTheme }) {
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const getInitials = (email) => {
    if (!email) return 'U';
    return email.charAt(0).toUpperCase();
  };

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-badge">&#x1F6E1;&#xFE0F;</div>
        <div className="logo-text">
          <h1>SPECTRA SHIELD</h1>
          <span>EDR / XDR Platform</span>
        </div>
      </div>
      <nav className="sidebar-nav">
        {NAV.map(item => (
          <a key={item.path} href="#" className={page === item.path ? 'active' : ''}
            onClick={e => { e.preventDefault(); navigate(item.path); }}>
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </a>
        ))}
      </nav>
      

      {/* Theme Toggle Button */}
      <button
        onClick={toggleTheme}
        className="theme-toggle-btn"
        title="Toggle Light/Dark Theme"
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginLeft: '20px',
          fontSize: '18px',
          padding: '4px',
          borderRadius: '6px',
          transition: 'transform 0.2s',
          color: 'var(--text)'
        }}
        onMouseEnter={(e) => { e.currentTarget.style.transform = 'scale(1.1)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1)'; }}
      >
        {theme === 'dark' ? '☀️' : '🌙'}
      </button>

    </div>
  );
}

// ---- TOAST ----
function Toast({ toasts, removeToast }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type === 'alert' ? 'toast-alert' : 'toast-info'}`}>
          <span className="toast-icon">{t.type === 'alert' ? '\u26A0\uFE0F' : '\u2139\uFE0F'}</span>
          <span className="toast-msg">{t.message}</span>
          <button className="toast-close" onClick={() => removeToast(t.id)}>&times;</button>
        </div>
      ))}
    </div>
  );
}

// ---- LOADING / EMPTY / ERROR ----
function Loading({ text }) { return <div className="loading"><div className="spinner" />{text || 'Loading...'}</div>; }
function EmptyState({ icon, text }) { return <div className="empty-state"><div className="empty-icon">{icon || '\u{1F4ED}'}</div><p>{text || 'No data available'}</p></div>; }
function ErrorState({ message, onRetry }) {
  return <div className="error-state"><p>&#9888; {message || 'An error occurred'}</p>{onRetry && <button className="btn btn-secondary btn-sm" onClick={onRetry}>Retry</button>}</div>;
}

// ---- SEVERITY BADGE ----
function SeverityBadge({ severity }) {
  const s = (severity || 'low').toLowerCase();
  return <span className={`badge ${SEVERITY_BADGE[s] || 'badge-low'}`}><span className="badge-dot" />{s}</span>;
}

function StatusBadge({ status }) {
  const s = (status || 'offline').toLowerCase();
  const cls = { online: 'badge-online', offline: 'badge-offline', compromised: 'badge-compromised', updating: 'badge-updating', pending: 'badge-pending', resolved: 'badge-resolved', acknowledged: 'badge-warning' };
  return <span className={`badge ${cls[s] || 'badge-offline'}`}><span className="badge-dot" />{status || 'Unknown'}</span>;
}

// ---- PAGINATION ----
function Pagination({ page, totalPages, onChange }) {
  if (totalPages <= 1) return null;
  return (
    <div className="pagination">
      <button disabled={page <= 1} onClick={() => onChange(page - 1)}>&laquo; Prev</button>
      <span className="page-info">Page {page} of {totalPages}</span>
      <button disabled={page >= totalPages} onClick={() => onChange(page + 1)}>Next &raquo;</button>
    </div>
  );
}

// ---- CHART COMPONENTS ----
function Gauge({ value, label, max = 100 }) {
  const pct = Math.min(value, max) / max;
  const angle = pct * 180;
  const color = value >= 80 ? 'var(--danger)' : value >= 50 ? 'var(--warning)' : 'var(--success)';
  return (
    <div className="gauge-container">
      <svg className="gauge-svg" viewBox="0 0 120 70">
        <path d="M 10 65 A 50 50 0 0 1 110 65" fill="none" className="gauge-track" strokeWidth="8" strokeLinecap="round" />
        <path d="M 10 65 A 50 50 0 0 1 110 65" fill="none" className="gauge-arc" stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={`${(angle / 180) * 157} 157`} />
        <text x="60" y="58" textAnchor="middle" fill="var(--text)" fontSize="18" fontWeight="700">{value}</text>
      </svg>
      <div className="gauge-label">{label || 'Score'}</div>
    </div>
  );
}

function PieChart({ data, size = 140 }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  let cumulative = 0;
  const slices = data.map((d, i) => {
    const pct = d.value / total;
    const startAngle = cumulative * 360;
    cumulative += pct;
    const endAngle = cumulative * 360;
    const startRad = (startAngle - 90) * Math.PI / 180;
    const endRad = (endAngle - 90) * Math.PI / 180;
    const r = 50;
    const cx = 70, cy = 70;
    const x1 = cx + r * Math.cos(startRad);
    const y1 = cy + r * Math.sin(startRad);
    const x2 = cx + r * Math.cos(endRad);
    const y2 = cy + r * Math.sin(endRad);
    const large = endAngle - startAngle > 180 ? 1 : 0;
    if (pct >= 0.999) {
      return <circle key={i} cx={cx} cy={cy} r={r} fill={d.color} />;
    }
    return <path key={i} d={`M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} Z`} fill={d.color} />;
  });
  return (
    <div className="flex-center" style={{ gap: '16px' }}>
      <svg className="pie-svg" width={size} height={size} viewBox="0 0 140 140">{slices}</svg>
      <div>
        {data.map((d, i) => (
          <div key={i} className="pie-legend-item">
            <div className="pie-legend-color" style={{ background: d.color }} />
            <span>{d.label}</span>
            <span style={{ color: 'var(--text2)', fontSize: '12px' }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BarChart({ data, color }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div className="bar-chart">
      {data.map((d, i) => (
        <div key={i} className="chart-bar-container">
          <span className="chart-bar-label">{d.label}</span>
          <div className="chart-bar-track">
            <div className="chart-bar-fill" style={{ width: `${(d.value / max) * 100}%`, background: d.color || color || 'var(--primary)' }} />
          </div>
          <span className="chart-bar-value">{d.value}</span>
        </div>
      ))}
    </div>
  );
}

// ============ PAGES ============

// ---- DASHBOARD ----
function Dashboard({ alerts, agents, onNavigate }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const exportReport = async (type) => {
    try {
      const res = await fetch(`/api/reports/export?type=${type}`, { headers: { ...getAuthHeaders() } });
      if (!res.ok) throw new Error(`Export failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `alerts_report.${type}`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { console.error('Export failed:', e); }
  };

  const fetchDashboard = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      apiFetch('/dashboard/summary'),
      apiFetch('/analytics/attack-vector-distribution'),
      apiFetch('/analytics/top-mitre-techniques'),
      apiFetch('/dashboard/alert-trend?hours=24'),
    ]).then(([summary, vectors, techniques, trend]) => {
      setData({ ...summary, attackVectors: Array.isArray(vectors) ? vectors : [], topTechniques: Array.isArray(techniques) ? techniques : [], alertTrend: Array.isArray(trend) ? trend : [] });
    }).catch(e => {
      setError(e.message);
      setData(null);
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchDashboard(); const id = setInterval(fetchDashboard, 10000); return () => clearInterval(id); }, [fetchDashboard]);

  if (loading && !data) return <Loading text="Loading dashboard..." />;
  if (error && !data) return <ErrorState message={error} onRetry={fetchDashboard} />;

  const d = data || {};
  const score = d.security_score ?? 0;
  const recentAlerts = alerts.slice(0, 8);
  const agentHealth = { online: d.online_agents || agents.filter(a => a.status === 'Online').length || 0, offline: d.offline_agents || agents.filter(a => a.status === 'Offline').length || 0, compromised: d.quarantined_agents || agents.filter(a => a.status === 'Compromised').length || 0 };
  const topTechniques = d.topTechniques || [];
  const attackVectors = d.attackVectors || [];
  const trendData = d.alertTrend?.map(t => ({ label: t.timestamp ? t.timestamp.slice(11, 16) : '', value: t.total })) || [];
  const totalAgents = d.total_agents ?? agents.length;
  const activeAlerts = d.open_alerts ?? alerts.filter(a => a.status === 'Open').length;
  const threatsBlocked = d.threats_blocked ?? 0;
  const systemsAtRisk = d.quarantined_agents ?? 0;
  const criticalCount = alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
  const trendPeak = Math.max(...trendData.map(x => x.value), 1);

  const totalHealth = agentHealth.online + agentHealth.offline + agentHealth.compromised || 1;

  return (
    <div>
      <div className="page-header">
        <div className="page-head-row">
          <h2>Dashboard</h2>
          <p>Security operations overview</p>
        </div>
        <div className="page-head-actions" style={{ marginLeft: 'auto', display: 'flex', gap: '6px' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => exportReport('csv')}>&#x2193; Export CSV</button>
          <button className="btn btn-secondary btn-sm" onClick={() => exportReport('json')}>&#x2193; Export JSON</button>
        </div>
      </div>

      <div className="grid grid-4 mb-24">
        <div className="card stat-card">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: 'var(--primary)' }}>&#x1F5A5;</div>
            <span className={`trend-badge ${agentHealth.online > 0 ? 'trend-up' : 'trend-neutral'}`}><span className="trend-arrow">&#x25B2;</span> {agentHealth.online} online</span>
          </div>
          <div className="stat-value">{totalAgents}</div>
          <div className="stat-label">Total Agents</div>
        </div>
        <div className="card stat-card">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: activeAlerts > 0 ? 'var(--danger)' : 'var(--success)' }}>&#x1F6A8;</div>
            <span className={`trend-badge ${criticalCount > 0 ? 'tone-danger' : 'trend-neutral'}`}>&#x26A0; {criticalCount} critical</span>
          </div>
          <div className="stat-value" style={{ color: activeAlerts > 0 ? 'var(--danger)' : 'var(--success)', textShadow: activeAlerts > 0 ? '0 0 22px rgba(239,68,68,0.55)' : 'none' }}>{activeAlerts}</div>
          <div className="stat-label">Active Alerts</div>
        </div>
        <div className="card stat-card">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: 'var(--success)' }}>&#x1F6E1;</div>
            <span className="trend-badge trend-up">+{threatsBlocked} today</span>
          </div>
          <div className="stat-value">{threatsBlocked}</div>
          <div className="stat-label">Threats Blocked Today</div>
        </div>
        <div className="card stat-card">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: systemsAtRisk > 0 ? 'var(--warning)' : 'var(--success)' }}>&#x26A0;</div>
            <span className={`trend-badge ${systemsAtRisk > 0 ? 'tone-danger' : 'tone-success'}`}>{systemsAtRisk > 0 ? 'At risk' : 'All clear'}</span>
          </div>
          <div className="stat-value" style={{ color: systemsAtRisk > 0 ? 'var(--warning)' : 'var(--text)' }}>{systemsAtRisk}</div>
          <div className="stat-label">Systems at Risk</div>
        </div>
      </div>

      <div className="dashboard-row">
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">24h window</span>
            Alert Trend (24h)
          </div>
          <div className="spark-chart" style={{ height: '120px', paddingTop: '8px' }}>
            {trendData.map((d, i) => (
              <div key={i} className="spark-col">
                <div className="spark-track">
                  <div className={`spark-bar ${d.value > 10 ? 'spark-hot' : ''}`} style={{ height: `${(d.value / trendPeak) * 100}%` }} />
                </div>
                <span className="spark-label">{d.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">posture</span>
            Security Score
          </div>
          <Gauge value={score} label="Overall Score" />
        </div>
      </div>

      <div className="dashboard-row">
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">latest events</span>
            Recent Alerts
          </div>
          {recentAlerts.length === 0 ? <EmptyState icon="&#x2705;" text="No recent alerts" /> : (
            <div className="table-wrap">
              <table className="table-solar">
                <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Agent</th><th>Tactic</th><th>Status</th></tr></thead>
                <tbody>
                  {recentAlerts.slice(0, 6).map(a => (
                    <tr key={a.id} className={`clickable row-${(a.severity || 'low').toLowerCase()}`} onClick={() => onNavigate('/alerts')}>
                      <td className="mono" style={{ fontSize: '12px', color: 'var(--text2)', whiteSpace: 'nowrap' }}>{a.timestamp || '--'}</td>
                      <td><span className={`alert-type-icon ${(a.type || 'file').toLowerCase()}`}>{a.type ? a.type[0] : 'F'}</span></td>
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td className="mono" style={{ color: 'var(--primary)' }}>{a.agentName || a.agent || '--'}</td>
                      <td className="mono" style={{ fontSize: '12px', color: 'var(--text2)' }}>{a.mitreTactic || '--'}</td>
                      <td><StatusBadge status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div>
          <div className="card mb-12">
            <div className="card-title">
              <span className="card-title-kicker">fleet health</span>
              Agent Health
            </div>
            <div className="health-bar">
              <div className="segment" style={{ width: `${(agentHealth.online / totalHealth) * 100}%`, background: 'var(--success)' }} />
              <div className="segment" style={{ width: `${(agentHealth.offline / totalHealth) * 100}%`, background: 'var(--text3)' }} />
              <div className="segment" style={{ width: `${(agentHealth.compromised / totalHealth) * 100}%`, background: 'var(--danger)' }} />
            </div>
            <div className="health-tooltip">
              <span><span style={{ color: 'var(--success)' }}>&#x25CF;</span> Online: {agentHealth.online}</span>
              <span><span style={{ color: 'var(--text3)' }}>&#x25CF;</span> Offline: {agentHealth.offline}</span>
              <span><span style={{ color: 'var(--danger)' }}>&#x25CF;</span> Compromised: {agentHealth.compromised}</span>
            </div>
          </div>
          <div className="card">
            <div className="card-title">
              <span className="card-title-kicker">attack surface</span>
              Top MITRE Techniques
            </div>
            {topTechniques.map((t, i) => (
              <div key={i} className="chart-bar-container">
                <span className="chart-bar-label" style={{ minWidth: '180px', fontSize: '11px' }}>
                  {t.technique_id ? `${t.technique_id} - ${t.technique_name}` : (t.technique_name || t.technique || 'Unknown')}
                </span>
                <div className="chart-bar-track">
                  <div className="chart-bar-fill" style={{ width: `${Math.min((t.count / Math.max(...topTechniques.map(x => x.count), 1)) * 100, 100)}%`, background: 'var(--danger)' }} />
                </div>
                <span className="chart-bar-value">{t.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">surfaces</span>
            Attack Vector Distribution
          </div>
          <BarChart data={attackVectors.map((v, i) => ({ label: v.name || v.type || v.label || 'Unknown', value: v.value || v.count || 0, color: ['#ff1744', '#ff9100', '#f59e0b', '#06b6d4', '#10b981', '#dc2626', '#f79f35', '#ff6f00'][i % 8] }))} />
        </div>
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">severity mix</span>
            Alert Distribution by Severity
          </div>
          <PieChart data={[
            { label: 'Critical', value: alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length || 0, color: '#ff0000' },
            { label: 'High', value: alerts.filter(a => (a.severity || '').toLowerCase() === 'high').length || 0, color: '#ff1744' },
            { label: 'Medium', value: alerts.filter(a => (a.severity || '').toLowerCase() === 'medium').length || 0, color: '#ff9100' },
            { label: 'Low', value: alerts.filter(a => (a.severity || '').toLowerCase() === 'low').length || 0, color: '#ffab00' },
          ]} />
        </div>
      </div>
    </div>
  );
}

// ---- AGENTS ----
function Agents({ onNavigate }) {
  const [agents, setAgents] = useState([]);
  const [filter, setFilter] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [expandTab, setExpandTab] = useState({});

  const fetchAgents = useCallback(() => {
    setLoading(true);
    setError(null);
    apiFetch('/agents').then(data => {
      const raw = Array.isArray(data) ? data : (data.agents || []);
      setAgents(raw.map(normalizeAgent));
    }).catch(e => {
      setError(e.message);
      setAgents([]);
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchAgents(); }, [fetchAgents]);

  const filtered = filter === 'All' ? agents : agents.filter(a => (a.status || '').toLowerCase() === filter.toLowerCase());
  const handleAction = async (id, action) => {
    try {
      const body = action === 'quarantine' ? { action: 'quarantine' } : undefined;
      await apiFetch(`/agents/${id}/${action}`, { method: 'POST', body: body ? JSON.stringify(body) : undefined });
      fetchAgents();
    } catch (e) { console.error(`Action ${action} failed:`, e); }
  };

  const handleDeleteAgent = async (id) => {
    if (!window.confirm("Are you sure you want to remove this agent? This will permanently delete the agent and all its associated telemetry.")) {
      return;
    }
    try {
      await apiFetch(`/agents/${id}`, { method: 'DELETE' });
      fetchAgents();
    } catch (e) { console.error(`Failed to remove agent:`, e); }
  };

  const toggleExpand = (id) => {
    setExpandedId(prev => prev === id ? null : id);
    if (!expandTab[id]) setExpandTab(prev => ({ ...prev, [id]: 'info' }));
  };

  const setTab = (id, tab) => setExpandTab(prev => ({ ...prev, [id]: tab }));

  return (
    <div>
      <div className="page-header">
        <div className="page-head-row">
          <h2>Agents</h2>
          <p>Manage and monitor all endpoints</p>
        </div>
      </div>

      <div className="filter-bar">
        <span className="filter-label">Status:</span>
        {AGENT_STATUSES.map(s => (
          <button key={s} className={`btn btn-sm ${filter === s ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setFilter(s)}>{s}</button>
        ))}
        <span style={{ flex: 1 }} />
        <button className="btn btn-primary btn-sm" onClick={fetchAgents}>&#x21BB; Refresh</button>
      </div>

      {loading ? <Loading text="Loading agents..." /> : error ? <ErrorState message={error} onRetry={fetchAgents} /> : filtered.length === 0 ? <EmptyState icon="&#x1F5A5;" text="No agents found" /> : (
        <div className="card panel-table" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-wrap">
            <table className="table-solar">
              <thead><tr><th>Name</th><th>OS</th><th>IP</th><th>Status</th><th>CPU</th><th>RAM</th><th>Last Seen</th><th>Actions</th></tr></thead>
              <tbody>
                {filtered.map(a => (
                  <React.Fragment key={a.id}>
                    <tr className={`clickable ${expandedId === a.id ? 'expanded' : ''} ${(a.status || 'offline').toLowerCase() === 'compromised' ? 'row-critical' : ''}`}
                      onClick={() => toggleExpand(a.id)}>
                      <td className="agent-name" style={{ fontWeight: 500 }}><span className="agent-mark">&#x1F5A5;&#xFE0F;</span>{a.name || 'Unknown'}</td>
                      <td style={{ fontSize: '12px' }}>{a.os || '--'}</td>
                      <td className="mono" style={{ fontSize: '12px', color: 'var(--info)' }}>{a.ip || '--'}</td>
                      <td><StatusBadge status={a.status} /></td>
                      <td className="meter-cell">
                        <div className="meter"><div className={`meter-fill ${a.cpu > 80 ? 'meter-hot' : ''}`} style={{ width: `${Math.min(a.cpu, 100)}%` }} /></div>
                        <span className="mono">{a.cpu}%</span>
                      </td>
                      <td className="meter-cell">
                        <div className="meter"><div className={`meter-fill ${a.ram > 80 ? 'meter-hot' : ''}`} style={{ width: `${Math.min(a.ram, 100)}%` }} /></div>
                        <span className="mono">{a.ram}%</span>
                      </td>
                      <td className="mono" style={{ fontSize: '12px', color: 'var(--text2)' }}>{a.lastSeen || '--'}</td>
                      <td>
                        <div className="flex gap-8">
                          <button className="btn btn-sm btn-secondary" onClick={e => { e.stopPropagation(); handleAction(a.id, 'scan'); }} title="Scan Agent">&#x1F50D;</button>
                          <button className="btn btn-sm btn-danger" onClick={e => { e.stopPropagation(); handleAction(a.id, 'quarantine'); }} title="Quarantine Agent">&#x1F6AB;</button>
                          <button className="btn btn-sm btn-danger" onClick={e => { e.stopPropagation(); handleDeleteAgent(a.id); }} title="Remove Agent">&times;</button>
                        </div>
                      </td>
                    </tr>
                    {expandedId === a.id && (
                      <tr className="expand-row"><td colSpan={8} style={{ padding: 0, background: 'var(--surface2)' }}>
                        <AgentDetail agent={a} activeTab={expandTab[a.id] || 'info'} onTab={(t) => setTab(a.id, t)} />
                      </td></tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function MiniChart({ data, color, height, label }) {
  const max = Math.max(...data, 1);
  return (
    <div className="mini-chart" style={{ flex: 1 }}>
      <div className="mini-chart-label" style={{ fontSize: '11px', color: 'var(--text2)', marginBottom: '4px' }}>{label}</div>
      <div className="spark-chart spark-chart-mini" style={{ height: `${height || 80}px` }}>
        {data.map((v, i) => (
          <div key={i} title={`${v}%`} className="spark-bar" style={{ height: `${(v / max) * 100}%`, background: color }} />
        ))}
      </div>
      <div className="mini-chart-summary" style={{ fontSize: '10px', color: 'var(--text3)', marginTop: '2px' }}>
        current: {data.length ? data[data.length - 1] : '--'}% | avg: {data.length ? (data.reduce((a, b) => a + b, 0) / data.length).toFixed(1) : '--'}%
      </div>
    </div>
  );
}

function AgentDetail({ agent, activeTab, onTab }) {
  const [detail, setDetail] = useState(null);
  const [tabData, setTabData] = useState({});
  const [selC2Event, setSelC2Event] = useState(null);
  const agentId = agent.id;

  useEffect(() => {
    if (!selC2Event) return;
    const handler = (e) => { if (e.key === 'Escape') setSelC2Event(null); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [selC2Event]);

  useEffect(() => {
    apiFetch(`/agents/${agentId}`).then(d => { setDetail(d); }).catch(() => { });
  }, [agentId]);

  useEffect(() => {
    if (activeTab === 'software') {
      apiFetch(`/agents/${agentId}/software-inventory`).then(d => setTabData(p => ({ ...p, software: Array.isArray(d) ? d : (d.software || []) }))).catch(() => { });
    } else if (activeTab === 'processes') {
      apiFetch(`/agents/${agentId}/processes`).then(d => setTabData(p => ({ ...p, processes: Array.isArray(d) ? d : (d.processes || []) }))).catch(() => { });
    } else if (activeTab === 'network') {
      apiFetch(`/agents/${agentId}/network`).then(d => setTabData(p => ({ ...p, network: Array.isArray(d) ? d : (d.connections || d.network || []) }))).catch(() => { });
    } else if (activeTab === 'integrity') {
      apiFetch(`/agents/${agentId}/file-integrity`).then(d => setTabData(p => ({ ...p, integrity: Array.isArray(d) ? d : (d.integrity || []) }))).catch(() => { });
    } else if (activeTab === 'alerts') {
      apiFetch(`/agents/${agentId}/alerts`).then(d => setTabData(p => ({ ...p, alerts: (Array.isArray(d) ? d : (d.alerts || [])).map(normalizeAlert) }))).catch(() => { });
    } else if (activeTab === 'process-tree') {
      apiFetch(`/agents/${agentId}/process-tree`).then(d => setTabData(p => ({ ...p, processTree: d }))).catch(() => { });
    } else if (activeTab === 'process-hashes') {
      apiFetch(`/agents/${agentId}/processes`).then(d => setTabData(p => ({ ...p, processHashes: Array.isArray(d) ? d.filter(x => x.hash) : [] }))).catch(() => { });
    } else if (activeTab === 'c2-beaconing') {
      apiFetch(`/agents/${agentId}/c2-beaconing`).then(d => setTabData(p => ({ ...p, c2: d }))).catch(() => { });
    }
    // Live monitoring fetch with auto-refresh
    if (activeTab === 'monitoring') {
      const fetchMon = () => apiFetch(`/agents/${agentId}/monitoring-logs`).then(d => {
        const logs = d.recent_logs || [];
        setTabData(p => ({ ...p, monitoring: { ...d, cpuData: logs.map(l => l.cpu_percent), ramData: logs.map(l => l.ram_percent) } }));
      }).catch(() => { });
      fetchMon();
      const id = setInterval(fetchMon, 10000);
      return () => clearInterval(id);
    }
  }, [activeTab, agentId]);

  const hw = detail || agent;
  const tabs = [
    { key: 'info', label: 'Info', icon: '\u{1F464}' },
    { key: 'monitoring', label: 'Monitoring', icon: '\u{1F493}' },
    { key: 'software', label: 'Software', icon: '\u{1F4E6}' },
    { key: 'processes', label: 'Processes', icon: '\u2699\uFE0F' },
    { key: 'process-tree', label: 'Process Tree', icon: '\u{1F333}' },
    { key: 'process-hashes', label: 'Hashes', icon: '\u{1F4C1}' },
    { key: 'network', label: 'Network', icon: '\u{1F310}' },
    { key: 'integrity', label: 'File Integrity', icon: '\u{1F4DC}' },
    { key: 'alerts', label: 'Alerts', icon: '\u{1F6A8}' },
    { key: 'c2-beaconing', label: 'C2 Beaconing', icon: '\u{1F4E1}' },
  ];

  return (
    <div className="expand-content">
      <div className="expand-tabs">
        {tabs.map(t => (
          <button key={t.key} className={`expand-tab ${activeTab === t.key ? 'active' : ''}`} onClick={() => onTab(t.key)}>
            <span className="tab-icon">{t.icon}</span>{t.label}
          </button>
        ))}
      </div>

      {activeTab === 'info' && (
        <>
          <div className="detail-grid">
            <DetailItem label="CPU" value={hw.cpu_usage != null ? `${hw.cpu_usage}%` : '--'} />
            <DetailItem label="RAM" value={hw.ram_total_gb ? `${hw.ram_used_gb ?? 0}/${hw.ram_total_gb} GB` : '--'} />
            <DetailItem label="MAC" value={hw.mac_address || '--'} />
            <DetailItem label="Disk" value={hw.disk_total_gb ? `${Math.round(hw.disk_total_gb - (hw.disk_used_gb ?? 0))}/${Math.round(hw.disk_total_gb)} GB` : '--'} />
            <DetailItem label="OS Version" value={hw.os_version || '--'} />
            <DetailItem label="Patch Level" value={hw.os_patch_level || '--'} />
            <DetailItem label="CPU Model" value={hw.cpu_model || '--'} />
            <DetailItem label="Hostname" value={hw.hostname || '--'} />
          </div>
        </>
      )}

      {activeTab === 'monitoring' && (
        <div>
          {tabData.monitoring ? (
            <>
              <div className="detail-grid" style={{ marginBottom: '16px' }}>
                <DetailItem label="Current CPU" value={`${tabData.monitoring.current_cpu ?? '--'}%`} />
                <DetailItem label="Current RAM" value={`${tabData.monitoring.current_ram_gb ?? '--'} GB`} />
                <DetailItem label="Avg CPU" value={`${tabData.monitoring.avg_cpu_percent ?? '--'}%`} />
                <DetailItem label="Avg RAM" value={`${tabData.monitoring.avg_ram_percent ?? '--'}%`} />
                <DetailItem label="Log Count" value={tabData.monitoring.log_count ?? '--'} />
              </div>
              <div className="mini-chart-row" style={{ display: 'flex', gap: '20px' }}>
                <MiniChart data={tabData.monitoring.cpuData || []} color="var(--primary)" height={100} label="CPU % (recent logs)" />
                <MiniChart data={tabData.monitoring.ramData || []} color="#ff9100" height={100} label="RAM % (recent logs)" />
              </div>
              <p className="live-refresh-note" style={{ fontSize: '11px', color: 'var(--text3)', marginTop: '8px' }}>
                <span className="live-dot live" /> Auto-refreshes every 10 seconds
              </p>
            </>
          ) : <EmptyState icon="&#x1F4CA;" text="No monitoring data yet. Make sure the agent is running." />}
        </div>
      )}

      {activeTab === 'software' && (
        <div>
          {(tabData.software && tabData.software.length) ? tabData.software.map((s, i) => (
            <div key={i} className="list-item"><span>{s.name || s}</span><span className="mono" style={{ color: 'var(--text2)', fontSize: '11px' }}>{s.version || ''}</span></div>
          )) : <EmptyState icon="&#x1F4E6;" text="No software data" />}
        </div>
      )}

      {activeTab === 'processes' && (
        <div>
          {(tabData.processes && tabData.processes.length) ? (
            <ul className="process-tree">
              {tabData.processes.map((p, i) => (
                <li key={i} className={p.parent_pid && p.parent_pid !== 0 && p.parent_pid !== p.pid ? 'process-child' : ''}>
                  <span className="proc-pid">{p.pid}</span>
                  <span className="proc-name">{p.name}</span>
                  {p.user && <span style={{ color: 'var(--text3)', marginLeft: '8px' }}>{p.user}</span>}
                  {p.cpu_percent != null && <span style={{ color: 'var(--text2)', marginLeft: '8px', fontSize: '11px' }}>{p.cpu_percent}%</span>}
                </li>
              ))}
            </ul>
          ) : <EmptyState icon="&#x2699;" text="No process data" />}
        </div>
      )}

      {activeTab === 'process-tree' && (
        <div>
          {tabData.processTree ? (
            <div className="process-tree-json mono" style={{ fontSize: '12px', fontFamily: 'JetBrains Mono, Consolas, monospace', whiteSpace: 'pre-wrap' }}>
              {JSON.stringify(tabData.processTree, null, 2)}
            </div>
          ) : <EmptyState icon="&#x1F9E0;" text="No process tree data" />}
        </div>
      )}

      {activeTab === 'process-hashes' && (
        <div>
          {(tabData.processHashes && tabData.processHashes.length) ? tabData.processHashes.map((p, i) => (
            <div key={i} className="list-item">
              <span style={{ fontSize: '12px' }}>{p.name}</span>
              <span className="mono" style={{ fontSize: '11px', color: 'var(--text2)' }}>{p.hash}</span>
            </div>
          )) : <EmptyState icon="&#x1F4C1;" text="No hash data" />}
        </div>
      )}

      {activeTab === 'network' && (
        <div>
          {(tabData.network && tabData.network.length) ? tabData.network.map((c, i) => (
            <div key={i} className="list-item">
              <span><span style={{ color: c.state === 'ESTABLISHED' ? 'var(--success)' : 'var(--text3)' }}>&#x25CF;</span> <span className="mono">{c.local_ip}:{c.local_port}</span></span>
              <span className="mono" style={{ color: 'var(--text2)' }}>&rarr; {c.remote_ip}:{c.remote_port}</span>
              <span style={{ color: 'var(--text2)', fontSize: '11px' }}>{c.state || '--'}</span>
            </div>
          )) : <EmptyState icon="&#x1F310;" text="No network connections" />}
        </div>
      )}

      {activeTab === 'integrity' && (
        <div>
          {(tabData.integrity && tabData.integrity.length) ? tabData.integrity.map((f, i) => (
            <div key={i} className="list-item">
              <span className="mono" style={{ fontSize: '12px' }}>{f.file_path || f.path || f}</span>
              <StatusBadge status={f.status || 'Unknown'} />
            </div>
          )) : <EmptyState icon="&#x1F4C1;" text="No file integrity data" />}
        </div>
      )}

      {activeTab === 'alerts' && (
        <div>
          {(tabData.alerts && tabData.alerts.length) ? tabData.alerts.map((a, i) => (
            <div key={i} className="list-item">
              <span>{a.type || a.alertType || 'Alert'}</span>
              <SeverityBadge severity={a.severity} />
              <span className="mono" style={{ fontSize: '12px', color: 'var(--text2)' }}>{a.timestamp || ''}</span>
            </div>
          )) : <EmptyState icon="&#x2705;" text="No alerts for this agent" />}
        </div>
      )}

      {activeTab === 'c2-beaconing' && (() => {
        const c2 = tabData.c2 || { total_beacons: 0, beaconing_detected: false, recent_events: [] };
        const events = c2.recent_events || [];

        return (
          <div>
            {/* Summary Grid */}
            <div className="detail-grid" style={{ marginBottom: '16px' }}>
              <DetailItem label="Total Beacons" value={c2.total_beacons} />
              <DetailItem label="Status" value={
                <span className={`badge ${c2.beaconing_detected ? 'badge-critical' : 'badge-low'}`}>
                  <span className="badge-dot" />{c2.beaconing_detected ? 'Active Beaconing' : 'Monitoring'}
                </span>
              } />
            </div>

            {/* Events Table or Empty State */}
            {events.length > 0 ? (
              <div className="table-responsive c2-table" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                <table className="table table-solar" style={{ width: '100%' }}>
                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Connections</th>
                      <th>Avg Interval</th>
                      <th>Variance</th>
                      <th>Detected At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((e, i) => (
                      <tr key={i} className={`clickable row-${e.variance < 25 ? 'critical' : 'low'}`} onClick={() => setSelC2Event(e)} style={{ cursor: 'pointer' }}>
                        <td className="mono">{e.src_ip}</td>
                        <td className="mono" style={{ color: 'var(--primary)', fontWeight: 600 }}>{e.dst_ip}</td>
                        <td>{e.connections}</td>
                        <td>{e.avg_interval.toFixed(1)}s</td>
                        <td>{e.variance.toFixed(2)}</td>
                        <td className="mono" style={{ fontSize: '11px', color: 'var(--text3)' }}>{e.detected_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState icon="🛡️" text="No C2 Beaconing activity detected for this agent. Monitoring is active." />
            )}

            {/* Portal Modal */}
            {selC2Event && ReactDOM.createPortal(
              <div
                className="modal-overlay"
                onClick={() => setSelC2Event(null)}
                style={{
                  position: 'fixed',
                  inset: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 9999,
                  background: 'rgba(0,0,0,0.6)',
                  backdropFilter: 'blur(4px)',
                }}
              >
                <div
                  className="modal"
                  onClick={e => e.stopPropagation()}
                  style={{
                    maxHeight: '95vh',
                    overflowY: 'auto',
                    width: '100%',
                    maxWidth: '550px',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: '12px',
                    display: 'flex',
                    flexDirection: 'column',
                  }}
                >
                  <div className="modal-header" style={{ borderBottom: '1px solid var(--border)', padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--text1)' }}>📡 C2 Beaconing Event Details</h3>
                    <button className="modal-close" onClick={() => setSelC2Event(null)} style={{ background: 'none', border: 'none', color: 'var(--text3)', fontSize: '20px', cursor: 'pointer' }}>&times;</button>
                  </div>
                  <div className="modal-body" style={{ padding: '20px', flex: 1, display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    {/* Banners */}
                    <div className="flex-between" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <SeverityBadge severity={selC2Event.variance < 25 ? 'high' : 'info'} />
                      <StatusBadge status={c2.beaconing_detected ? 'Active' : 'Monitoring'} />
                    </div>

                    {/* Connection Section */}
                    <div className="detail-section">
                      <h5 style={{ margin: '0 0 8px 0', fontSize: '12px', color: 'var(--primary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Connection Details</h5>
                      <div className="detail-grid">
                        <div className="detail-item"><div className="label">Source IP</div><div className="value mono">{selC2Event.src_ip}</div></div>
                        <div className="detail-item"><div className="label">Destination IP</div><div className="value mono" style={{ color: 'var(--primary)', fontWeight: 600 }}>{selC2Event.dst_ip}</div></div>
                        <div className="detail-item"><div className="label">Connections</div><div className="value">{selC2Event.connections}</div></div>
                        <div className="detail-item"><div className="label">Avg Interval</div><div className="value">{selC2Event.avg_interval.toFixed(1)}s</div></div>
                        <div className="detail-item"><div className="label">Variance</div><div className="value">{selC2Event.variance.toFixed(2)}</div></div>
                      </div>
                    </div>

                    {/* Classification Section */}
                    <div className="detail-section">
                      <h5 style={{ margin: '0 0 8px 0', fontSize: '12px', color: 'var(--primary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Security Classification</h5>
                      <div className="detail-grid">
                        <div className="detail-item"><div className="label">Severity</div><div className="value">{selC2Event.variance < 25 ? 'High' : 'Info'}</div></div>
                        <div className="detail-item"><div className="label">Risk Score</div><div className="value">{selC2Event.variance < 25 ? '80/100' : '0/100'}</div></div>
                        <div className="detail-item"><div className="label">Agent Name</div><div className="value">{hw.hostname || hw.name || 'Unknown'}</div></div>
                        <div className="detail-item"><div className="label">MITRE ID</div><div className="value mono">T1071</div></div>
                        <div className="detail-item"><div className="label">Technique</div><div className="value">Application Layer Protocol</div></div>
                        <div className="detail-item"><div className="label">Tactic</div><div className="value">Command & Control</div></div>
                      </div>
                    </div>

                    {/* Timeline */}
                    <div className="detail-section">
                      <h5 style={{ margin: '0 0 8px 0', fontSize: '12px', color: 'var(--primary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Timeline</h5>
                      <div className="detail-item">
                        <div className="label">Detected At</div>
                        <div className="value">{selC2Event.detected_at}</div>
                      </div>
                    </div>

                    {/* Raw Data Collapsible */}
                    <div className="detail-section">
                      <details style={{ cursor: 'pointer', background: 'rgba(255,255,255,0.01)', border: '1px solid var(--border)', borderRadius: '6px', padding: '10px' }}>
                        <summary style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text2)', outline: 'none', userSelect: 'none' }}>📦 Toggle Raw JSON Data</summary>
                        <pre style={{ margin: '8px 0 0 0', padding: '10px', background: 'rgba(0,0,0,0.2)', borderRadius: '4px', overflowX: 'auto', fontSize: '11px', fontFamily: 'JetBrains Mono, Consolas, monospace', color: 'var(--text)' }}>
                          {JSON.stringify(selC2Event, null, 2)}
                        </pre>
                      </details>
                    </div>
                  </div>
                  <div className="modal-footer" style={{ borderTop: '1px solid var(--border)', padding: '16px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                    <button className="btn btn-secondary" onClick={() => setSelC2Event(null)}>Close</button>
                  </div>
                </div>
              </div>,
              document.body
            )}
          </div>
        );
      })()}
    </div>
  );
}

function DetailItem({ label, value }) {
  return (
    <div className="detail-item">
      <div className="label">{label}</div>
      <div className="value mono">{value || '--'}</div>
    </div>
  );
}

// ---- ALERTS ----
function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({ severity: 'All', type: 'All', status: 'All', tactic: 'All' });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [page, setPage] = useState(1);
  const perPage = 15;

  const fetchAlerts = useCallback(() => {
    setLoading(true);
    setError(null);
    apiFetch('/alerts').then(data => {
      const raw = Array.isArray(data) ? data : (data.alerts || []);
      setAlerts(raw.map(normalizeAlert));
    }).catch(e => {
      setError(e.message);
      setAlerts([]);
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchAlerts(); const id = setInterval(fetchAlerts, 10000); return () => clearInterval(id); }, [fetchAlerts]);

  const filtered = alerts.filter(a => {
    if (filters.severity !== 'All' && (a.severity || '').toLowerCase() !== filters.severity.toLowerCase()) return false;
    if (filters.type !== 'All' && (a.type || '').toLowerCase() !== filters.type.toLowerCase()) return false;
    if (filters.status !== 'All' && (a.status || '').toLowerCase() !== filters.status.toLowerCase()) return false;
    if (filters.tactic !== 'All' && (a.mitreTactic || '').toLowerCase() !== filters.tactic.toLowerCase()) return false;
    return true;
  });

  const totalPages = Math.ceil(filtered.length / perPage);
  const paged = filtered.slice((page - 1) * perPage, page * perPage);

  const handleAction = async (id, action) => {
    try {
      await apiFetch(`/alerts/${id}/${action}`, { method: 'POST', body: JSON.stringify({}) });
      fetchAlerts();
      if (selectedAlert && (selectedAlert.id === id || selectedAlert.alertId === id)) {
        setSelectedAlert(prev => prev ? { ...prev, status: action === 'acknowledge' ? 'acknowledged' : 'resolved' } : null);
      }
    } catch (e) { console.error(`Alert action failed:`, e); }
  };

  const handleResolveAll = async () => {
    if (!window.confirm("Are you sure you want to resolve all alerts? This will mark all unresolved alerts as resolved.")) {
      return;
    }
    try {
      await apiFetch(`/alerts/resolve-all`, { method: 'POST', body: JSON.stringify({}) });
      fetchAlerts();
      if (selectedAlert) {
        setSelectedAlert(prev => prev ? { ...prev, status: 'resolved' } : null);
      }
    } catch (e) { console.error(`Resolve all alerts failed:`, e); }
  };


  const uniqueTactics = ['All', ...new Set(alerts.map(a => a.mitreTactic).filter(Boolean))];
  const severityCounts = SEVERITIES.map(s => ({ label: s, count: alerts.filter(a => (a.severity || '').toLowerCase() === s).length }));

  const typeIcon = (type) => {
    const t = (type || 'file').toLowerCase();
    const icons = { file: '\u{1F4C4}', network: '\u{1F310}', process: '\u{2699}', identity: '\u{1F464}', behavior: '\u{1F916}' };
    return icons[t] || '\u{1F4C4}';
  };
  const sevMax = Math.max(...severityCounts.map(s => s.count), 1);

  return (
    <div>
      <div className="page-header">
        <div className="page-head-row">
          <h2>Alerts</h2>
          <p>Security event investigation and response</p>
        </div>
      </div>

      <div className="grid grid-4 mb-16">
        {severityCounts.map(s => (
          <div key={s.label} className={`card stat-card severity-stat sev-${s.label}`} style={{ padding: '12px 16px' }}>
            <div className="flex-between">
              <span className="stat-label sev-label"><span className="badge-dot" />{s.label}</span>
              <span className="stat-value" style={{ fontSize: '20px', color: SEVERITY_COLORS[s.label] }}>{s.count}</span>
            </div>
            <div className="sev-track"><div className="sev-fill" style={{ width: `${(s.count / sevMax) * 100}%`, background: SEVERITY_COLORS[s.label] }} /></div>
          </div>
        ))}
      </div>

      <div className="filter-bar">
        <select className="filter-select" value={filters.severity} onChange={e => { setFilters(f => ({ ...f, severity: e.target.value })); setPage(1); }}>
          <option value="All">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select className="filter-select" value={filters.type} onChange={e => { setFilters(f => ({ ...f, type: e.target.value })); setPage(1); }}>
          {ALERT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="filter-select" value={filters.status} onChange={e => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1); }}>
          {ALERT_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="filter-select" value={filters.tactic} onChange={e => { setFilters(f => ({ ...f, tactic: e.target.value })); setPage(1); }}>
          {uniqueTactics.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <span style={{ flex: 1 }} />
        <button className="btn btn-danger btn-sm" onClick={handleResolveAll} style={{ marginRight: '8px' }}>&#x2713; Resolve All</button>
        <button className="btn btn-primary btn-sm" onClick={fetchAlerts}>&#x21BB; Refresh</button>
      </div>

      {loading ? <Loading text="Loading alerts..." /> : error ? <ErrorState message={error} onRetry={fetchAlerts} /> : paged.length === 0 ? <EmptyState icon="&#x2705;" text="No alerts match your filters" /> : (
        <div className="card panel-table" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-responsive" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
            <table className="table-solar">
              <thead><tr><th>Timestamp</th><th>Type</th><th>Severity</th><th>Agent</th><th>MITRE Tactic</th><th>Technique</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                {paged.map(a => (
                  <tr key={a.id || a.alertId} className={`clickable row-${(a.severity || 'low').toLowerCase()}`} onClick={() => setSelectedAlert(a)}>
                    <td className="mono" style={{ fontSize: '12px', color: 'var(--text2)', whiteSpace: 'nowrap' }}>{a.timestamp || '--'}</td>
                    <td><span className={`alert-type-icon ${(a.type || 'file').toLowerCase()}`}>{typeIcon(a.type)}</span></td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td className="mono" style={{ color: 'var(--primary)' }}>{a.agentName || a.agent || '--'}</td>
                    <td className="mono" style={{ fontSize: '12px', color: 'var(--text2)' }}>{a.mitreTactic || '--'}</td>
                    <td className="mono" style={{ fontSize: '12px', color: 'var(--text2)' }}>{a.mitreTechnique || a.technique || '--'}</td>
                    <td><StatusBadge status={a.status} /></td>
                    <td>
                      <div className="flex gap-8" onClick={e => e.stopPropagation()}>
                        {!['resolved', 'dismissed'].includes((a.status || '').toLowerCase()) && (
                          <>
                            <button className="btn btn-sm btn-secondary" onClick={() => handleAction(a.id || a.alertId, 'acknowledge')}>Ack</button>
                            <button className="btn btn-sm btn-primary" onClick={() => handleAction(a.id || a.alertId, 'resolve')}>Resolve</button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ padding: '8px 12px' }}>
            <Pagination page={page} totalPages={totalPages} onChange={setPage} />
          </div>
        </div>
      )}

      {selectedAlert && (
        <AlertDetail alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onAction={(action) => handleAction(selectedAlert.id || selectedAlert.alertId, action)} />
      )}
    </div>
  );
}

function getFriendlyExplanation(alert, details) {
  const type = (alert.type || alert.alertType || '').toLowerCase();
  const severity = (alert.severity || 'low').toLowerCase();
  const titleText = (alert.title || '').toLowerCase();

  let friendlyType = "Security Event";
  let icon = "🔔";
  let whatHappened = "Our security system detected unusual activity on your computer and logged it for review.";
  let whyItMatters = "Keeping track of unusual system activity helps detect potential security threats before they can cause damage.";
  let recommendedAction = "Review the details to make sure you recognize the program. If you didn't start this program yourself, it's safest to resolve or quarantine it.";

  if (type === 'next_gen_av' || type === 'malware' || titleText.includes('blocked') || titleText.includes('prevented') || titleText.includes('malware')) {
    friendlyType = "Malicious Program Prevented";
    icon = "🛡️";
    whatHappened = `We blocked a file named "${details.file_path || details.process_name || alert.process_name || 'unknown'}" from running because it matched known security threats (malware).`;
    whyItMatters = "Malicious software (malware) can steal your personal files, spy on your password keystrokes, or infect other programs on your computer.";
    recommendedAction = "No immediate action is required since we successfully blocked the threat. You can run a full virus scan if you want to be extra safe.";
  } else if (type === 'ransomware_canary' || type === 'ransomware' || titleText.includes('ransomware') || titleText.includes('canary')) {
    friendlyType = "Potential Ransomware Action Detected";
    icon = "🚨";
    whatHappened = "A program tried to modify or lock multiple files in your folders in a very short period of time, which resembles ransomware behavior.";
    whyItMatters = "Ransomware locks your personal folders (documents, photos) and demands payment (a ransom) to unlock them.";
    recommendedAction = "Click the 'Resolve' button immediately to quarantine this process. If this is a personal script you ran on purpose, you can safely acknowledge it.";
  } else if (type === 'process_anomaly' || type === 'process_tree' || type === 'process') {
    friendlyType = "Unusual Program Behavior";
    icon = "⚙️";
    whatHappened = "A program on your computer performed an unexpected action (for example, a document viewer or web browser trying to run system command screens).";
    whyItMatters = "Hackers often take control of legitimate software to run hidden commands without your knowledge.";
    recommendedAction = "If you were not actively opening a file or installing updates when this popped up, click 'Resolve' to stop and isolate the program.";
  } else if (type === 'network_dpi' || type === 'network' || type === 'c2_beaconing' || type === 'beaconing' || type === 'port_scan') {
    friendlyType = "Suspicious Network Connection";
    icon = "🌐";
    whatHappened = "A program on your computer is trying to connect to an unrecognized or potentially unsafe address on the internet.";
    whyItMatters = "Infected programs often try to connect back to a 'command center' operated by hackers to send out stolen data or download more instructions.";
    recommendedAction = "If you don't recognize the program or connection, click 'Resolve' to block network access for this program.";
  } else if (type === 'file_integrity' || type === 'file_tamper' || type === 'registry_monitoring') {
    friendlyType = "System File Modification";
    icon = "📂";
    whatHappened = "An important configuration or system file was modified.";
    whyItMatters = "Malicious programs modify system settings to disable security controls or ensure they remain on your system even after restarting.";
    recommendedAction = "If you didn't recently run an official Windows Update or install trusted software, review the changed file name and click 'Resolve' to restore standard settings.";
  } else if (type === 'misconfiguration') {
    friendlyType = "Weak Security Settings Found";
    icon = "🔧";
    whatHappened = "We found that some settings (like your firewall or remote login options) are turned off or set insecurely.";
    whyItMatters = "Weak settings act like an unlocked window, making it easier for network attackers to find and compromise your computer.";
    recommendedAction = "Enable the firewall and apply strong password policies in your security settings to resolve this issue.";
  }

  let safetyVerdict = "Review Required";
  let safetyColor = "var(--warning)";
  if (severity === 'critical') {
    safetyVerdict = "Immediate Action Recommended";
    safetyColor = "#ff1744";
  } else if (severity === 'high') {
    safetyVerdict = "High Risk - Review Soon";
    safetyColor = "#ff9100";
  }

  if ((alert.status || '').toLowerCase() === 'resolved') {
    safetyVerdict = "Resolved - System Secure";
    safetyColor = "var(--success)";
  } else if ((alert.status || '').toLowerCase() === 'acknowledged') {
    safetyVerdict = "Acknowledged";
    safetyColor = "var(--text3)";
  }

  return { friendlyType, icon, whatHappened, whyItMatters, recommendedAction, safetyVerdict, safetyColor };
}

function AlertDetail({ alert, onClose, onAction }) {
  const [activeSubTab, setActiveSubTab] = React.useState('summary');
  const details = alert.details ? (typeof alert.details === 'string' ? JSON.parse(alert.details) : alert.details) : {};
  const explanation = getFriendlyExplanation(alert, details);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>{explanation.icon}</span> {explanation.friendlyType}
          </h3>
          <button className="modal-close" onClick={onClose}>&times;</button>
        </div>
        <div className="modal-body">
          {/* Tab Selector */}
          <div className="section-tabs alert-tabs" style={{ display: 'flex', gap: '8px', marginBottom: '20px', borderBottom: '1px solid var(--border)', paddingBottom: '10px' }}>
            <button
              className={`btn ${activeSubTab === 'summary' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveSubTab('summary')}
              style={{ padding: '8px 16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              🛡️ Simple Summary
            </button>
            <button
              className={`btn ${activeSubTab === 'technical' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveSubTab('technical')}
              style={{ padding: '8px 16px', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              💻 Technical Details
            </button>
          </div>

          {activeSubTab === 'summary' && (
            <div>
              {/* Safety Verdict Card */}
              <div className="verdict-card" style={{
                borderRadius: '10px',
                background: 'rgba(255, 255, 255, 0.02)',
                borderLeft: `4px solid ${explanation.safetyColor}`,
                borderTop: '1px solid var(--border)',
                borderRight: '1px solid var(--border)',
                borderBottom: '1px solid var(--border)',
                padding: '16px',
                marginBottom: '20px'
              }}>
                <div className="verdict-label" style={{ fontSize: '11px', color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>Security Status</div>
                <div className="safety-verdict" style={{ fontSize: '18px', fontWeight: 700, color: explanation.safetyColor, marginTop: '4px' }}>{explanation.safetyVerdict}</div>
                <div style={{ fontSize: '12px', color: 'var(--text2)', marginTop: '8px' }}>
                  <strong>Alert Severity:</strong> {alert.severity || 'Low'} | <strong>Status:</strong> {alert.status || 'Open'}
                </div>
              </div>

              {/* Cards Grid */}
              <div className="explain-stack" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div className="explain-card" style={{ borderRadius: '10px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)', padding: '16px' }}>
                  <h5 style={{ color: 'var(--primary)', margin: '0 0 8px 0', fontSize: '13px', fontWeight: 600 }}>🔍 What Happened?</h5>
                  <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text)', margin: 0 }}>{explanation.whatHappened}</p>
                  <p style={{ fontSize: '11px', color: 'var(--text3)', marginTop: '8px', fontStyle: 'italic', margin: '8px 0 0 0' }}>
                    <strong>Original logs show:</strong> "{alert.description || 'Security alert detected'}"
                  </p>
                </div>

                <div className="explain-card" style={{ borderRadius: '10px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)', padding: '16px' }}>
                  <h5 style={{ color: 'var(--primary)', margin: '0 0 8px 0', fontSize: '13px', fontWeight: 600 }}>💡 Why is this important?</h5>
                  <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text)', margin: 0 }}>{explanation.whyItMatters}</p>
                </div>

                <div className="explain-card" style={{ borderRadius: '10px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)', padding: '16px' }}>
                  <h5 style={{ color: 'var(--primary)', margin: '0 0 8px 0', fontSize: '13px', fontWeight: 600 }}>🛡️ Recommended Action</h5>
                  <p style={{ fontSize: '13px', lineHeight: '1.6', color: 'var(--text)', margin: 0 }}>{explanation.recommendedAction}</p>
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'technical' && (
            <div>
              <div className="flex-between mb-16">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
              </div>

              <div className="detail-section">
                <h5>Description</h5>
                <p style={{ fontSize: '14px', lineHeight: '1.6', color: 'var(--text)' }}>{alert.description || 'Security alert detected'}</p>
              </div>

              <div className="detail-grid">
                <div className="detail-section">
                  <h5>MITRE ATT&CK</h5>
                  <div className="detail-item"><div className="label">Tactic</div><div className="value">{alert.mitreTactic || '--'}</div></div>
                  <div className="detail-item"><div className="label">Technique ID</div><div className="value mono">{alert.mitreTechniqueId || '--'}</div></div>
                  <div className="detail-item"><div className="label">Technique Name</div><div className="value">{alert.mitreTechnique || '--'}</div></div>
                  <div className="detail-item"><div className="label">Score</div><div className="value">{alert.score != null ? alert.score : '--'}</div></div>
                </div>
                <div className="detail-section">
                  <h5>Affected System</h5>
                  <div className="detail-item"><div className="label">Agent ID</div><div className="value mono">{alert.agent_id || '--'}</div></div>
                  <div className="detail-item"><div className="label">Hostname</div><div className="value">{alert.agentName || alert.hostname || '--'}</div></div>
                </div>
              </div>

              {details && Object.keys(details).length > 0 && (
                <div className="detail-section">
                  <h5>Additional Details</h5>
                  <div className="detail-grid">
                    {Object.entries(details).map(([k, v]) => (
                      <div key={k} className="detail-item">
                        <div className="label">{k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</div>
                        <div className="value mono">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="detail-section">
                <h5>Timeline</h5>
                <div className="detail-item"><div className="label">Created</div><div className="value">{alert.timestamp || alert.firstSeen || '--'}</div></div>
                {alert.acknowledged_at && <div className="detail-item"><div className="label">Acknowledged</div><div className="value">{alert.acknowledged_at}</div></div>}
                {alert.resolved_at && <div className="detail-item"><div className="label">Resolved</div><div className="value">{alert.resolved_at}</div></div>}
              </div>
            </div>
          )}
        </div>
        <div className="modal-footer">
          {!['acknowledged', 'resolved', 'dismissed'].includes((alert.status || '').toLowerCase()) && (
            <button className="btn btn-secondary" onClick={() => onAction('acknowledge')}>Acknowledge</button>
          )}
          {!['resolved', 'dismissed'].includes((alert.status || '').toLowerCase()) && (
            <button className="btn btn-primary" onClick={() => onAction('resolve')}>&#x2713; Resolve</button>
          )}
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ---- THREAT MAP ----
function ThreatMap() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lookupValue, setLookupValue] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [expandedLookupSections, setExpandedLookupSections] = useState({});


  const fetchThreats = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      apiFetch('/threats/summary'),
      apiFetch('/threats/intel?limit=20'),
      apiFetch('/analytics/attack-vector-distribution'),
      apiFetch('/dashboard/alert-trend?hours=24'),
    ]).then(([summary, intel, vectors, trend]) => {
      setData({
        ...summary,
        intel: Array.isArray(intel) ? intel : [],
        attackVectors: Array.isArray(vectors) ? vectors : [],
        alertTrend: Array.isArray(trend) ? trend : [],
      });
    }).catch(e => {
      setError(e.message);
      setData(null);
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchThreats(); const id = setInterval(fetchThreats, 30000); return () => clearInterval(id); }, [fetchThreats]);


  const toggleLookupSection = (section) => {
    setExpandedLookupSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const handleLookup = async () => {
    const val = lookupValue.trim();
    if (!val) return;
    setLookupLoading(true);
    setLookupResult(null);
    setExpandedLookupSections({ overview: true });
    try {
      const res = await apiFetch(`/threat-intel/lookup?indicator=${encodeURIComponent(val)}`);
      setLookupResult(res);
    } catch (e) {
      try {
        const res = await apiFetch('/threats/lookup', { method: 'POST', body: JSON.stringify({ value: val }) });
        setLookupResult(res);
      } catch (e2) { setLookupResult({ found: false, value: val, error: e2.message }); }
    }
    setLookupLoading(false);
  };

  const threats = data || {};
  const intelList = threats.intel || [];
  const badIPs = intelList.filter(i => i.indicator_type === 'ip').map(i => i.value).slice(0, 5);
  const badHashes = intelList.filter(i => i.indicator_type === 'hash').map(i => i.value).slice(0, 3);
  const badDomains = intelList.filter(i => i.indicator_type === 'domain').map(i => i.value).slice(0, 4);
  const alertTimeline = threats.alertTrend || [];
  const attackVectors = threats.attackVectors || [];
  const activeThreats = threats.total_iocs ?? 0;
  const blockedToday = threats.matched_connections ?? 0;
  const uniqueIPs = threats.ip_iocs ?? 0;
  const trendPeak = Math.max(...alertTimeline.map(x => x.total), 1);

  return (
    <div>
      <div className="page-header">
        <div className="page-head-row">
          <h2>Threat Map & Analytics</h2>
          <p>Threat intelligence and attack analysis</p>
        </div>
      </div>

      <div className="grid grid-3 mb-24">
        <div className="card stat-card threat-stat">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: 'var(--danger)' }}>&#x2620;</div>
            <span className="trend-badge tone-danger">live threat feed</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--danger)', textShadow: activeThreats > 0 ? '0 0 22px rgba(239,68,68,0.5)' : 'none' }}>{activeThreats}</div>
          <div className="stat-label">Active Threats</div>
        </div>
        <div className="card stat-card threat-stat">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: 'var(--success)' }}>&#x1F6E1;</div>
            <span className="trend-badge trend-up">neutralized</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>{blockedToday}</div>
          <div className="stat-label">Blocked Today</div>
        </div>
        <div className="card stat-card threat-stat">
          <div className="stat-head">
            <div className="stat-icon" style={{ color: 'var(--info)' }}>&#x1F5FA;&#xFE0F;</div>
            <span className="trend-badge trend-neutral">tracked</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--info)' }}>{uniqueIPs}</div>
          <div className="stat-label">Unique Bad IPs</div>
        </div>
      </div>

      <div className="grid grid-2 mb-24">
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">intel stream</span>
            Threat Intelligence Feed
          </div>
          <div className="section-tabs" style={{ marginBottom: '12px' }}>
            {['Bad IPs', 'Hashes', 'Domains'].map(t => (
              <button key={t} className="section-tab active" style={{ cursor: 'default' }}>{t}</button>
            ))}
          </div>
          <div className="intel-columns" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px' }}>
            <div><div className="detail-item"><div className="label">Malicious IPs</div>{intelList.filter(i => i.indicator_type === 'ip').slice(0, 10).map((item, i) => <div key={i} className="value mono" style={{ fontSize: '11px', padding: '2px 0' }}>{item.value}</div>)}</div></div>
            <div><div className="detail-item"><div className="label">File Hashes</div>{intelList.filter(i => i.indicator_type === 'hash').slice(0, 5).map((item, i) => <div key={i} className="value mono" style={{ fontSize: '10px', padding: '2px 0' }}>{item.value.slice(0, 32)}...</div>)}</div></div>
            <div><div className="detail-item"><div className="label">Malicious Domains</div>{intelList.filter(i => i.indicator_type === 'domain').slice(0, 10).map((item, i) => <div key={i} className="value mono" style={{ fontSize: '11px', padding: '2px 0' }}>{item.value}</div>)}</div></div>
          </div>

          <div className="mt-12" style={{ borderTop: '1px solid var(--border)', paddingTop: '12px' }}>
            <div className="card-title" style={{ fontSize: '13px', marginBottom: '8px' }}>Threat Lookup</div>
            <div className="flex gap-8">
              <input type="search" className="lookup-input" placeholder="IP, hash, or domain..." value={lookupValue}
                onChange={e => setLookupValue(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLookup()}
                style={{ flex: 1 }} />
              <button className="btn btn-primary btn-sm" onClick={handleLookup} disabled={lookupLoading}>
                {lookupLoading ? '...' : '\u{1F50D} Check'}
              </button>
            </div>
            {lookupResult && (
              <div className="lookup-results" style={{ borderRadius: '10px', border: '1px solid var(--border)', overflow: 'hidden', marginTop: '12px', boxShadow: '0 2px 12px rgba(0,0,0,0.2)' }}>
                {/* === INVESTIGATION HEADER === */}
                <div className="lookup-header" style={{ background: 'linear-gradient(135deg, var(--surface3) 0%, var(--surface) 100%)', borderBottom: '2px solid var(--primary)', padding: '14px 16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="lookup-type-chip" style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.5px', padding: '3px 8px', background: 'var(--surface2)', borderRadius: '4px', color: 'var(--text2)' }}>{lookupResult.indicator_type}</span>
                        <SeverityBadge severity={lookupResult.severity} />
                        <span style={{ fontSize: '11px', color: 'var(--text3)', background: 'var(--surface2)', padding: '2px 8px', borderRadius: '10px' }}>Source: {lookupResult.source || 'N/A'}</span>
                      </div>
                      <span className="mono" style={{ fontSize: '14px', fontWeight: 600, wordBreak: 'break-all', color: 'var(--text1)' }}>{lookupResult.value}</span>
                    </div>
                    <div style={{ textAlign: 'right', fontSize: '11px', color: 'var(--text3)', display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-end' }}>
                      {lookupResult.first_seen && <span>First seen: {new Date(lookupResult.first_seen).toLocaleDateString()}</span>}
                      {lookupResult.last_seen && <span>Last seen: {new Date(lookupResult.last_seen).toLocaleDateString()}</span>}
                      {lookupResult.confidence && <span>Confidence: {lookupResult.confidence}</span>}
                    </div>
                  </div>
                  {/* Confidence Meter */}
                  {lookupResult.reputation_score !== undefined && (
                    <div style={{ marginTop: '8px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text3)', marginBottom: '3px' }}>
                        <span>Reputation Score</span>
                        <span style={{ fontWeight: 700, color: lookupResult.reputation_score >= 70 ? 'var(--danger)' : lookupResult.reputation_score >= 40 ? 'var(--warning)' : 'var(--success)' }}>{lookupResult.reputation_score}/100 ({lookupResult.reputation_label})</span>
                      </div>
                      <div className="reputation-track" style={{ height: '6px', background: 'var(--surface2)', borderRadius: '3px', overflow: 'hidden' }}>
                        <div className="reputation-fill" style={{ height: '100%', width: `${lookupResult.reputation_score}%`, borderRadius: '3px', background: lookupResult.reputation_score >= 70 ? 'linear-gradient(90deg, #ef4444, #dc2626)' : lookupResult.reputation_score >= 40 ? 'linear-gradient(90deg, #f59e0b, #eb7a12)' : 'linear-gradient(90deg, #10b981, #059669)', transition: 'width 0.5s ease' }} />
                      </div>
                    </div>
                  )}
                </div>

                {!lookupResult.found ? (
                  <div className="lookup-clean" style={{ padding: '20px 16px', background: 'var(--surface)', textAlign: 'center' }}>
                    <div className="lookup-clean-icon" style={{ fontSize: '24px', marginBottom: '8px', color: 'var(--success)' }}>&#x2714;</div>
                    <div style={{ color: 'var(--success)', fontSize: '14px', fontWeight: 600 }}>No threats detected</div>
                    <div style={{ fontSize: '12px', color: 'var(--text3)', marginTop: '6px' }}>
                      {lookupResult.dnsbl && `${lookupResult.dnsbl.hits.length}/${lookupResult.dnsbl.checked.length} DNSBLs`}
                      {lookupResult.dnsbl && lookupResult.virustotal ? ' | ' : ''}
                      {lookupResult.virustotal && !lookupResult.virustotal.error && `VT: ${lookupResult.virustotal.malicious}/${lookupResult.virustotal.total} engines`}
                      {(() => { const err = lookupResult.virustotal_error || lookupResult.vt_error; if (err === 'no_key') return <span style={{ color: 'var(--warning)' }}>Set VIRUSTOTAL_API_KEY in config.py</span>; if (err && err !== 'no_key') return <span style={{ color: 'var(--danger)' }}>VT API: {err}</span>; return null; })()}
                    </div>
                  </div>
                ) : (
                  <div style={{ background: 'var(--surface)' }}>
                    {/* ===== SECTION: THREAT OVERVIEW ===== */}
                    <InvestSection title="Threat Overview" sectionKey="overview" expanded={expandedLookupSections} onToggle={toggleLookupSection} defaultOpen>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', fontSize: '12px' }}>
                        <InfoRow label="Indicator" value={lookupResult.value} mono />
                        <InfoRow label="Type" value={lookupResult.indicator_type} />
                        <InfoRow label="Severity" value={<SeverityBadge severity={lookupResult.severity} />} />
                        <InfoRow label="Confidence" value={lookupResult.confidence} />
                        <InfoRow label="Reputation Score" value={`${lookupResult.reputation_score}/100 (${lookupResult.reputation_label})`} />
                        <InfoRow label="Source" value={lookupResult.source || 'N/A'} />
                        {lookupResult.first_seen && <InfoRow label="First Seen" value={new Date(lookupResult.first_seen).toLocaleDateString()} />}
                        {lookupResult.last_seen && <InfoRow label="Last Seen" value={new Date(lookupResult.last_seen).toLocaleDateString()} />}
                      </div>
                      {lookupResult.description && (
                        <div className="threat-desc" style={{ marginTop: '8px', padding: '8px 10px', background: 'rgba(239,68,68,0.05)', borderRadius: '6px', borderLeft: '3px solid var(--danger)', fontSize: '12px', color: 'var(--text2)', lineHeight: '1.5' }}>
                          {lookupResult.description}
                        </div>
                      )}
                    </InvestSection>

                    {/* ===== SECTION: WHY MALICIOUS ===== */}
                    {lookupResult.what_it_does && lookupResult.what_it_does.length > 0 && (
                      <InvestSection title="Why Is This Malicious?" sectionKey="why" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                        <div style={{ fontSize: '12px', lineHeight: '1.6' }}>
                          {lookupResult.malware_family && (
                            <div style={{ marginBottom: '8px', display: 'flex', gap: '6px', alignItems: 'center' }}>
                              <span style={{ color: 'var(--text3)' }}>Threat Category:</span>
                              <span style={{ fontWeight: 600, color: 'var(--danger)', background: 'rgba(239,68,68,0.1)', padding: '2px 10px', borderRadius: '4px', fontSize: '12px' }}>{lookupResult.malware_family}</span>
                            </div>
                          )}
                          <div style={{ display: 'grid', gap: '4px' }}>
                            {lookupResult.what_it_does.map((d, i) => (
                              <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', padding: '4px 8px', background: 'var(--surface2)', borderRadius: '6px' }}>
                                <span style={{ color: 'var(--danger)', fontWeight: 700, fontSize: '13px' }}>&#x2022;</span>
                                <span style={{ color: 'var(--text2)' }}>{d}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </InvestSection>
                    )}

                    {/* ===== SECTION: IMPACT ASSESSMENT ===== */}
                    {lookupResult.impact && lookupResult.impact.length > 0 && (
                      <InvestSection title="Impact Assessment" sectionKey="impact" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '8px' }}>
                          {lookupResult.impact.map((d, i) => (
                            <div key={i} style={{ padding: '10px', background: 'rgba(239,68,68,0.04)', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.12)' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '16px' }}>{['\u{1F512}', '\u{1F4CD}', '\u{1F310}', '\u{1F4E4}', '\u{1F500}', '\u{1F4A3}', '\u{1F6E1}\uFE0F'][i % 7]}</span>
                                <span style={{ fontSize: '12px', color: 'var(--text2)', lineHeight: '1.4' }}>{d}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </InvestSection>
                    )}

                    {/* ===== SECTION: TECHNICAL DETAILS ===== */}
                    <InvestSection title="Technical Details" sectionKey="tech" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px', fontSize: '12px' }}>
                        {lookupResult.indicator_type === 'ip' && lookupResult.virustotal && (
                          <>
                            {lookupResult.virustotal.country && <InfoRow label="Country" value={lookupResult.virustotal.country} />}
                            {lookupResult.virustotal.asn && <InfoRow label="ASN" value={`AS${lookupResult.virustotal.asn}`} />}
                            {lookupResult.virustotal.network && <InfoRow label="Network" value={lookupResult.virustotal.network} />}
                            {lookupResult.virustotal.regional_internet_registry && <InfoRow label="RIR" value={lookupResult.virustotal.regional_internet_registry} />}
                            {lookupResult.virustotal.reputation !== undefined && <InfoRow label="VT Reputation" value={lookupResult.virustotal.reputation} />}
                          </>
                        )}
                        {lookupResult.indicator_type === 'hash' && lookupResult.virustotal && (
                          <>
                            {lookupResult.virustotal.meaningful_name && <InfoRow label="File Name" value={lookupResult.virustotal.meaningful_name} mono />}
                            {lookupResult.virustotal.type_description && <InfoRow label="File Type" value={lookupResult.virustotal.type_description} />}
                            {lookupResult.virustotal.size > 0 && <InfoRow label="Size" value={`${(lookupResult.virustotal.size / 1024).toFixed(1)} KB`} />}
                            {lookupResult.virustotal.malicious !== undefined && <InfoRow label="Detections" value={`${lookupResult.virustotal.malicious}/${lookupResult.virustotal.total}`} />}
                          </>
                        )}
                        {lookupResult.indicator_type === 'domain' && lookupResult.virustotal && (
                          <>
                            {lookupResult.virustotal.reputation !== undefined && <InfoRow label="VT Reputation" value={lookupResult.virustotal.reputation} />}
                            {lookupResult.virustotal.categories && Object.keys(lookupResult.virustotal.categories).length > 0 && (
                              <InfoRow label="Categories" value={Object.values(lookupResult.virustotal.categories).slice(0, 3).join(', ')} />
                            )}
                          </>
                        )}
                        {/* DNSBL info for IPs */}
                        {lookupResult.dnsbl && lookupResult.dnsbl.checked.length > 0 && (
                          <div style={{ gridColumn: '1 / -1', marginTop: '4px' }}>
                            <div style={{ color: 'var(--text3)', fontWeight: 600, marginBottom: '4px', fontSize: '11px', textTransform: 'uppercase' }}>DNS Blocklist Results</div>
                            {lookupResult.dnsbl.hits.length > 0 ? (
                              lookupResult.dnsbl.hits.map((h, i) => (
                                <div key={i} style={{ display: 'flex', gap: '8px', padding: '2px 0', fontSize: '12px' }}>
                                  <span style={{ color: 'var(--danger)', fontWeight: 600 }}>BLOCKED</span>
                                  <span style={{ color: 'var(--text3)' }}>{h.list}: {h.category}</span>
                                </div>
                              ))
                            ) : (
                              <div style={{ color: 'var(--success)', fontSize: '12px' }}>&#x2713; Clean on all {lookupResult.dnsbl.checked.length} blocklists</div>
                            )}
                          </div>
                        )}
                      </div>
                      {/* VT tags */}
                      {lookupResult.virustotal && lookupResult.virustotal.tags && lookupResult.virustotal.tags.length > 0 && (
                        <div style={{ marginTop: '8px' }}>
                          <div style={{ color: 'var(--text3)', fontWeight: 600, marginBottom: '4px', fontSize: '11px', textTransform: 'uppercase' }}>Tags</div>
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {lookupResult.virustotal.tags.map((t, i) => (
                              <span key={i} className="tag-chip" style={{ fontSize: '10px', padding: '2px 8px', background: 'rgba(245,158,11,0.08)', borderRadius: '3px', color: 'var(--text3)', border: '1px solid rgba(245,158,11,0.16)' }}>{t}</span>
                            ))}
                          </div>
                        </div>
                      )}
                    </InvestSection>

                    {/* ===== SECTION: BEHAVIOR ANALYSIS ===== */}
                    {lookupResult.what_it_does && lookupResult.what_it_does.length > 0 && (
                      <InvestSection title="Behavior Analysis" sectionKey="behavior" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                        <div style={{ display: 'grid', gap: '6px' }}>
                          {[
                            { label: 'Communication', icon: '\u{1F4E1}', items: lookupResult.what_it_does.filter(d => d.toLowerCase().includes('c2') || d.toLowerCase().includes('command') || d.toLowerCase().includes('remote') || d.toLowerCase().includes('network') || d.toLowerCase().includes('download')) },
                            { label: 'Persistence', icon: '\u{1F4C0}', items: lookupResult.what_it_does.filter(d => d.toLowerCase().includes('persist') || d.toLowerCase().includes('boot') || d.toLowerCase().includes('autostart') || d.toLowerCase().includes('survive')) },
                            { label: 'Credential Theft', icon: '\u{1F511}', items: lookupResult.what_it_does.filter(d => d.toLowerCase().includes('credential') || d.toLowerCase().includes('keylog') || d.toLowerCase().includes('password') || d.toLowerCase().includes('steal')) },
                            { label: 'Exfiltration', icon: '\u{1F4E4}', items: lookupResult.what_it_does.filter(d => d.toLowerCase().includes('exfiltrat') || d.toLowerCase().includes('data') || d.toLowerCase().includes('sensitive') || d.toLowerCase().includes('harvest')) },
                            { label: 'General', icon: '\u{2699}\uFE0F', items: lookupResult.what_it_does.filter(d => !['c2', 'command', 'remote', 'network', 'download', 'persist', 'boot', 'autostart', 'survive', 'credential', 'keylog', 'password', 'steal', 'exfiltrat', 'data', 'sensitive', 'harvest'].some(k => d.toLowerCase().includes(k))) },
                          ].filter(g => g.items.length > 0).map((g, i) => (
                            <div key={i} style={{ padding: '8px 10px', background: 'var(--surface2)', borderRadius: '6px' }}>
                              <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text1)', marginBottom: '4px' }}>{g.icon} {g.label}</div>
                              {g.items.map((d, j) => <div key={j} style={{ fontSize: '12px', color: 'var(--text2)', padding: '1px 0', paddingLeft: '16px' }}>&bull; {d}</div>)}
                            </div>
                          ))}
                        </div>
                      </InvestSection>
                    )}

                    {/* ===== SECTION: MITRE ATT&CK ===== */}
                    {lookupResult.mitre_attck && lookupResult.mitre_attck.length > 0 && (
                      <InvestSection title="MITRE ATT&CK Mapping" sectionKey="mitre" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                        <div style={{ display: 'grid', gap: '6px' }}>
                          {lookupResult.mitre_attck.map((m, i) => (
                            <div key={i} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '8px 10px', background: 'var(--surface2)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                              <div className="mitre-chip" style={{ background: 'rgba(245,158,11,0.1)', borderRadius: '6px', padding: '6px 10px', textAlign: 'center', minWidth: '70px' }}>
                                <div style={{ fontSize: '10px', color: 'var(--text3)', fontWeight: 600 }}>{m.tactic_id}</div>
                                <div style={{ fontSize: '11px', color: 'var(--primary)', fontWeight: 700 }}>{m.tactic}</div>
                              </div>
                              <div style={{ flex: 1 }}>
                                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text1)' }}>
                                  <span className="mono" style={{ color: 'var(--primary)', fontSize: '11px' }}>{m.technique_id}</span> {m.technique}
                                </div>
                                <div style={{ fontSize: '11px', color: 'var(--text3)' }}>Tactic: {m.tactic}</div>
                              </div>
                              <span style={{ fontSize: '18px', color: 'var(--text3)' }}>&#x2192;</span>
                            </div>
                          ))}
                        </div>
                      </InvestSection>
                    )}

                    {/* ===== SECTION: VIRUSTOTAL ENGINES ===== */}
                    {lookupResult.virustotal && lookupResult.virustotal.engines && Object.keys(lookupResult.virustotal.engines).length > 0 && (
                      <InvestSection title={`VirusTotal Detection (${lookupResult.virustotal.malicious}/${lookupResult.virustotal.total})`} sectionKey="vt" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: '3px' }}>
                          {Object.entries(lookupResult.virustotal.engines).slice(0, 30).map(([name, info]) => (
                            <div key={name} style={{ fontSize: '11px', padding: '3px 8px', background: info.verdict === 'malicious' ? 'rgba(239,68,68,0.06)' : 'rgba(245,158,11,0.04)', borderRadius: '4px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{ color: 'var(--text2)' }}>{name}</span>
                              <span style={{ padding: '1px 6px', borderRadius: '3px', fontSize: '10px', fontWeight: 600, background: info.verdict === 'malicious' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)', color: info.verdict === 'malicious' ? 'var(--danger)' : 'var(--warning)' }}>{info.verdict}</span>
                            </div>
                          ))}
                        </div>
                        {Object.keys(lookupResult.virustotal.engines).length > 30 && (
                          <div style={{ fontSize: '11px', color: 'var(--text3)', marginTop: '6px', textAlign: 'center' }}>+{Object.keys(lookupResult.virustotal.engines).length - 30} more engines</div>
                        )}
                      </InvestSection>
                    )}

                    {/* ===== SECTION: RECOMMENDED ACTIONS ===== */}
                    {lookupResult.recommended_actions && lookupResult.recommended_actions.length > 0 && (
                      <InvestSection title="Recommended Actions" sectionKey="actions" expanded={expandedLookupSections} onToggle={toggleLookupSection}>
                        <div style={{ display: 'grid', gap: '6px' }}>
                          {lookupResult.recommended_actions.map((d, i) => (
                            <div key={i} style={{ display: 'flex', gap: '10px', alignItems: 'center', padding: '8px 10px', background: i === 0 && ['critical', 'high'].includes(lookupResult.severity) ? 'rgba(239,68,68,0.06)' : 'var(--surface2)', borderRadius: '6px', border: i === 0 && ['critical', 'high'].includes(lookupResult.severity) ? '1px solid rgba(239,68,68,0.22)' : '1px solid var(--border)' }}>
                              <div style={{ width: '22px', height: '22px', borderRadius: '50%', background: i === 0 && ['critical', 'high'].includes(lookupResult.severity) ? 'var(--danger)' : 'var(--surface3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 700, color: i === 0 && ['critical', 'high'].includes(lookupResult.severity) ? '#fff' : 'var(--text2)', flexShrink: 0 }}>{i + 1}</div>
                              <span style={{ fontSize: '12px', color: 'var(--text2)', lineHeight: '1.4' }}>{d}</span>
                            </div>
                          ))}
                        </div>
                      </InvestSection>
                    )}
                  </div>
                )}
              </div>
            )}

          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">radar sweep</span>
            Alert Timeline (24h)
          </div>
          {loading ? <Loading /> : alertTimeline.length === 0 ? <EmptyState text="No alerts in last 24 hours" /> : (
            <div className="spark-chart spark-chart-vertical" style={{ height: '100px', paddingTop: '8px' }}>
              {alertTimeline.map((d, i) => (
                <div key={i} className="spark-col">
                  <div className="spark-track">
                    <div className={`spark-bar ${d.total > 0 ? 'spark-hot' : 'spark-idle'}`} style={{ height: `${(d.total / trendPeak) * 100}%` }} />
                  </div>
                  <span className="spark-label" style={{ writingMode: 'vertical-lr', textOrientation: 'mixed' }}>{d.timestamp ? d.timestamp.slice(11, 16) : ''}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-title">
          <span className="card-title-kicker">surfaces</span>
          Attack Vector Distribution
        </div>
        {loading ? <Loading /> : attackVectors.length === 0 ? <EmptyState text="No alert data yet" /> : (
          <BarChart data={attackVectors.map((v, i) => ({
            label: v.name || v.type || 'Unknown',
            value: v.value || v.count || 0,
            color: ['#ff1744', '#ff9100', '#f59e0b', '#06b6d4', '#10b981', '#dc2626', '#f79f35', '#ff6f00'][i % 8],
          }))} />
        )}
      </div>
    </div>
  );
}

// ---- SETTINGS ----
function Settings() {
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [policies, setPolicies] = useState([
    { id: 'realTime', name: 'Real-Time Protection', desc: 'Continuous file scanning and behavior monitoring', enabled: true },
    { id: 'firewall', name: 'Firewall Rules', desc: 'Automated firewall rule management', enabled: true },
    { id: 'usbBlock', name: 'USB Device Control', desc: 'Block unauthorized USB storage devices', enabled: true },
    { id: 'webFilter', name: 'Web Filtering', desc: 'Block malicious and phishing URLs', enabled: false },
    { id: 'appControl', name: 'Application Control', desc: 'Whitelist-based application execution policy', enabled: true },
    { id: 'scriptControl', name: 'Script Control', desc: 'Monitor and restrict script execution', enabled: false },
    { id: 'ransomware', name: 'Ransomware Protection', desc: 'Advanced ransomware behavior detection', enabled: true },
    { id: 'networkIntel', name: 'Network Threat Intel', desc: 'Real-time network threat intelligence feed', enabled: false },
  ]);

  const [whitelist, setWhitelist] = useState([]);
  const [newApp, setNewApp] = useState('');

  const [blockedUSB, setBlockedUSB] = useState([]);
  const [newDeviceID, setNewDeviceID] = useState('');
  const [newDeviceName, setNewDeviceName] = useState('');

  const [firewallRules, setFirewallRules] = useState([]);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleProtocol, setNewRuleProtocol] = useState('TCP');
  const [newRulePort, setNewRulePort] = useState('');
  const [newRuleAction, setNewRuleAction] = useState('Block');

  const [canaryFiles, setCanaryFiles] = useState([]);
  const [newCanaryPath, setNewCanaryPath] = useState('');

  const fetchSettings = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      apiFetch('/policies'),
      apiFetch('/policies/app-whitelist'),
      apiFetch('/policies/blocked-devices'),
      apiFetch('/policies/firewall-rules'),
      apiFetch('/policies/canary-files')
    ]).then(([d, wl, dev, fw, cf]) => {
      setSettings(d);
      if (d && typeof d === 'object') {
        setPolicies(prev => prev.map(p => ({
          ...p,
          enabled: d[p.id] === 'true' || d[p.id] === true,
        })));
      }
      if (wl && wl.whitelist) {
        setWhitelist(wl.whitelist);
      }
      if (dev && dev.devices) {
        setBlockedUSB(dev.devices);
      }
      if (fw) {
        setFirewallRules(fw);
      }
      if (cf) {
        setCanaryFiles(cf);
      }
    }).catch(err => {
      console.error('Failed to load settings:', err);
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchSettings(); }, [fetchSettings]);

  const togglePolicy = async (id) => {
    const next = !policies.find(p => p.id === id)?.enabled;
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, enabled: next } : p));
    try {
      await apiFetch('/policies', { method: 'POST', body: JSON.stringify({ key: id, value: String(next) }) });
    } catch (e) { console.error('Failed to save policy:', e); }
  };

  const addWhitelist = async () => {
    if (newApp.trim()) {
      const app = newApp.trim();
      try {
        const res = await apiFetch('/policies/app-whitelist', {
          method: 'POST',
          body: JSON.stringify({ name: app, path: '', hash: '', vendor: '' })
        });
        if (res && res.whitelist) {
          setWhitelist(res.whitelist);
        }
        setNewApp('');
      } catch (e) {
        console.error('Failed to add to whitelist:', e);
      }
    }
  };

  const removeWhitelist = async (app) => {
    try {
      const res = await apiFetch(`/policies/app-whitelist/${app}`, {
        method: 'DELETE'
      });
      if (res && res.whitelist) {
        setWhitelist(res.whitelist);
      }
    } catch (e) {
      console.error('Failed to remove from whitelist:', e);
    }
  };

  const blockUSBDevice = async () => {
    if (newDeviceID.trim() && newDeviceName.trim()) {
      try {
        const res = await apiFetch('/policies/blocked-devices', {
          method: 'POST',
          body: JSON.stringify({
            device_id: newDeviceID.trim(),
            device_name: newDeviceName.trim(),
            device_type: 'usb',
            reason: 'Blocked by admin'
          })
        });
        if (res && res.devices) {
          setBlockedUSB(res.devices);
        }
        setNewDeviceID('');
        setNewDeviceName('');
      } catch (e) {
        console.error('Failed to block USB device:', e);
      }
    }
  };

  const unblockUSBDevice = async (deviceId) => {
    try {
      const res = await apiFetch(`/policies/blocked-devices/${deviceId}/unblock`, {
        method: 'POST'
      });
      if (res && res.devices) {
        setBlockedUSB(res.devices);
      }
    } catch (e) {
      console.error('Failed to unblock USB device:', e);
    }
  };

  const addFirewallRule = async () => {
    if (newRuleName.trim() && newRulePort) {
      try {
        await apiFetch('/policies/firewall-rules', {
          method: 'POST',
          body: JSON.stringify({
            name: newRuleName.trim(),
            protocol: newRuleProtocol,
            local_port: parseInt(newRulePort, 10) || 0,
            action: newRuleAction.toLowerCase(),
            direction: 'inbound',
            remote_ip: 'any',
            enabled: true
          })
        });
        const rules = await apiFetch('/policies/firewall-rules');
        setFirewallRules(rules);
        setNewRuleName('');
        setNewRulePort('');
      } catch (e) {
        console.error('Failed to add firewall rule:', e);
      }
    }
  };

  const deleteFirewallRule = async (ruleId) => {
    try {
      await apiFetch(`/policies/firewall-rules/${ruleId}`, {
        method: 'DELETE'
      });
      const rules = await apiFetch('/policies/firewall-rules');
      setFirewallRules(rules);
    } catch (e) {
      console.error('Failed to delete firewall rule:', e);
    }
  };

  const addCanaryFile = async () => {
    if (newCanaryPath.trim()) {
      try {
        await apiFetch('/policies/canary-files', {
          method: 'POST',
          body: JSON.stringify({
            file_path: newCanaryPath.trim()
          })
        });
        const files = await apiFetch('/policies/canary-files');
        setCanaryFiles(files);
        setNewCanaryPath('');
      } catch (e) {
        console.error('Failed to add canary file:', e);
      }
    }
  };

  const deleteCanaryFile = async (canaryId) => {
    try {
      await apiFetch(`/policies/canary-files/${canaryId}`, {
        method: 'DELETE'
      });
      const files = await apiFetch('/policies/canary-files');
      setCanaryFiles(files);
    } catch (e) {
      console.error('Failed to delete canary file:', e);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div className="page-head-row">
          <h2>Settings & Policies</h2>
          <p>Security configuration and management</p>
        </div>
      </div>

      <div className="policy-grid">
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">engagement rules</span>
            Security Policies
          </div>
          {policies.map(p => (
            <div key={p.id} className="toggle-row">
              <div className="toggle-info">
                <div className="toggle-name">{p.name}</div>
                <div className="toggle-desc">{p.desc}</div>
              </div>
              <div className={`toggle-switch ${p.enabled ? 'active' : ''}`} onClick={() => togglePolicy(p.id)}>
                <div className="toggle-knob" />
              </div>
            </div>
          ))}
        </div>

        <div>
          <div className="card mb-16">
            <div className="card-title">
              <span className="card-title-kicker">allow list</span>
              Application Whitelist
            </div>
            {whitelist.map((app, i) => (
              <div key={i} className="list-item">
                <span className="mono" style={{ fontSize: '12px' }}>{app}</span>
                <button className="btn btn-sm btn-danger" onClick={() => removeWhitelist(app)}>Remove</button>
              </div>
            ))}
            <div className="flex gap-8 mt-12">
              <input type="search" className="lookup-input" placeholder="App name (e.g., chrome.exe)" value={newApp} onChange={e => setNewApp(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addWhitelist()} style={{ flex: 1 }} />
              <button className="btn btn-primary btn-sm" onClick={addWhitelist}>Add</button>
            </div>
          </div>

          <div className="card mb-16">
            <div className="card-title">
              <span className="card-title-kicker">peripheral control</span>
              Blocked USB Devices
            </div>
            {blockedUSB.length === 0 ? (
              <EmptyState icon="💾" text="No USB devices currently blocked" />
            ) : (
              blockedUSB.map((d, i) => (
                <div key={i} className="list-item">
                  <div>
                    <span className="mono" style={{ fontSize: '11px' }}>{d.device_id}</span>
                    <br />
                    <span style={{ fontSize: '12px', color: 'var(--text2)' }}>{d.device_name}</span>
                  </div>
                  <button className="btn btn-sm btn-danger" onClick={() => unblockUSBDevice(d.device_id)}>Unblock</button>
                </div>
              ))
            )}
            <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <input type="text" className="lookup-input" placeholder="Device ID (e.g. USB\VID_0781...)" value={newDeviceID} onChange={e => setNewDeviceID(e.target.value)} />
              <div style={{ display: 'flex', gap: '8px' }}>
                <input type="text" className="lookup-input" placeholder="Friendly Name (e.g. SanDisk)" value={newDeviceName} onChange={e => setNewDeviceName(e.target.value)} style={{ flex: 1 }} />
                <button className="btn btn-primary btn-sm" onClick={blockUSBDevice}>Block</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-2 mt-24">
        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">network egress</span>
            Firewall Rules
          </div>
          {firewallRules.length === 0 ? (
            <EmptyState icon="🛡️" text="No firewall rules configured" />
          ) : (
            <div className="table-wrap">
              <table className="table-solar" style={{ width: '100%' }}>
                <thead><tr><th>Name</th><th>Protocol</th><th>Port</th><th>Action</th><th></th></tr></thead>
                <tbody>
                  {firewallRules.map((r, i) => (
                    <tr key={i}>
                      <td>{r.name}</td>
                      <td className="mono" style={{ fontSize: '12px' }}>{r.protocol}</td>
                      <td className="mono">{r.local_port || 'any'}</td>
                      <td><StatusBadge status={r.action === 'allow' ? 'Allow' : 'Block'} /></td>
                      <td style={{ textAlign: 'right' }}>
                        <button className="btn btn-sm btn-danger" onClick={() => deleteFirewallRule(r.id)}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="settings-rule-editor" style={{ marginTop: '16px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            <input type="text" className="lookup-input" placeholder="Rule Name" value={newRuleName} onChange={e => setNewRuleName(e.target.value)} style={{ flex: '1 1 120px' }} />
            <select value={newRuleProtocol} onChange={e => setNewRuleProtocol(e.target.value)} style={{ padding: '8px 12px', border: '1px solid var(--border)', borderRadius: '8px', background: 'var(--card-bg)', color: 'var(--text1)' }}>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>
            <input type="number" className="lookup-input" placeholder="Port" value={newRulePort} onChange={e => setNewRulePort(e.target.value)} style={{ width: '80px' }} />
            <select value={newRuleAction} onChange={e => setNewRuleAction(e.target.value)} style={{ padding: '8px 12px', border: '1px solid var(--border)', borderRadius: '8px', background: 'var(--card-bg)', color: 'var(--text1)' }}>
              <option value="Block">Block</option>
              <option value="Allow">Allow</option>
            </select>
            <button className="btn btn-primary btn-sm" onClick={addFirewallRule}>Add Rule</button>
          </div>
        </div>

        <div className="card">
          <div className="card-title">
            <span className="card-title-kicker">deception grid</span>
            Canary Files
          </div>
          {canaryFiles.length === 0 ? (
            <EmptyState icon="🐦" text="No canary files deployed" />
          ) : (
            canaryFiles.map((f, i) => (
              <div key={i} className="list-item">
                <div>
                  <span className="mono" style={{ fontSize: '12px' }}>{f.file_path}</span>
                  <br />
                  <span style={{ fontSize: '11px', color: 'var(--text3)' }}>Name: {f.file_name}</span>
                </div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <StatusBadge status={f.is_triggered ? 'Triggered' : 'Intact'} />
                  <button className="btn btn-sm btn-danger" onClick={() => deleteCanaryFile(f.id)}>Remove</button>
                </div>
              </div>
            ))
          )}
          <div style={{ marginTop: '16px', display: 'flex', gap: '8px' }}>
            <input type="text" className="lookup-input" placeholder="File Path (e.g. C:\canary_passwords.docx)" value={newCanaryPath} onChange={e => setNewCanaryPath(e.target.value)} style={{ flex: 1 }} />
            <button className="btn btn-primary btn-sm" onClick={addCanaryFile}>Add Canary</button>
          </div>
        </div>
      </div>

      <div className="card mt-24">
        <div className="card-title">
          <span className="card-title-kicker">endpoint enrollment</span>
          Claim Agent
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text2)', marginBottom: '12px' }}>
          Link a newly registered agent to your account using its one-time token.
        </p>
        <ClaimAgentForm />
      </div>
    </div>
  );
}

function ClaimAgentForm() {
  const [hostname, setHostname] = useState('');
  const [token, setToken] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleClaim = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    setLoading(true);
    try {
      const data = await apiFetch('/auth/claim-agent', { method: 'POST', body: JSON.stringify({ hostname, one_time_token: token }) });
      setMessage(`Agent "${data.hostname}" claimed successfully!`);
      setHostname('');
      setToken('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleClaim}>
      <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
        <div style={{ flex: '1 1 200px' }}>
          <label style={{ color: 'var(--text2)', fontSize: '11px', display: 'block', marginBottom: '4px' }}>Agent Hostname</label>
          <input type="text" className="lookup-input" value={hostname} onChange={e => setHostname(e.target.value)} required placeholder="e.g. DESKTOP-ABC123"
            style={{ width: '100%', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', boxSizing: 'border-box' }} />
        </div>
        <div style={{ flex: '2 1 300px' }}>
          <label style={{ color: 'var(--text2)', fontSize: '11px', display: 'block', marginBottom: '4px' }}>One-Time Token</label>
          <input type="text" className="lookup-input" value={token} onChange={e => setToken(e.target.value)} required placeholder="Paste the one-time token from the agent"
            style={{ width: '100%', padding: '10px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontFamily: 'JetBrains Mono, Consolas, monospace', fontSize: '12px', boxSizing: 'border-box' }} />
        </div>
        <button type="submit" disabled={loading} className="btn btn-primary" style={{ padding: '8px 20px', height: '34px' }}>
          {loading ? 'Claiming...' : 'Claim Agent'}
        </button>
      </div>
      {message && <div style={{ color: '#10b981', fontSize: '13px', marginTop: '8px' }}>{message}</div>}
      {error && <div style={{ color: '#ef4444', fontSize: '13px', marginTop: '8px' }}>{error}</div>}
    </form>
  );
}

// ---- MITRE MATRIX ----
function MitreMatrix() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTactic, setSelectedTactic] = useState(null);

  useEffect(() => {
    apiFetch('/alerts').then(data => {
      const raw = Array.isArray(data) ? data : (data.alerts || []);
      setAlerts(raw.map(normalizeAlert));
    }).catch(() => { }).finally(() => setLoading(false));
  }, []);

  const getCoverage = (tacticName) => {
    const matching = alerts.filter(a => (a.mitreTactic || '').toLowerCase() === tacticName.toLowerCase());
    if (matching.length === 0) return 'none';
    const detected = matching.filter(a => ['resolved', 'acknowledged'].includes((a.status || '').toLowerCase())).length;
    const ratio = detected / matching.length;
    if (ratio >= 0.7) return 'detected';
    if (ratio >= 0.3) return 'partial';
    return 'not-detected';
  };

  const techniquesForTactic = (tactic) => {
    return MITRE_TECHNIQUES.filter(t => t.tactic === tactic);
  };

  const getTechniqueAlerts = (techniqueId) => {
    return alerts.filter(a => (a.mitreTechniqueId || a.techniqueId || '').toUpperCase() === techniqueId.toUpperCase() || (a.mitreTechnique || a.technique || '').toLowerCase().includes(techniqueId.toLowerCase()));
  };

  const cols = 7;
  const rows = Math.ceil(MITRE_TACTICS.length / cols);

  return (
    <div>
      <div className="page-header">
        <div className="page-head-row">
          <h2>MITRE ATT&CK Matrix</h2>
          <p>Detection coverage mapping by tactic and technique</p>
        </div>
      </div>

      <div className="mitre-legend flex gap-12 mb-16">
        <span className="legend-item"><div className="pie-legend-color" style={{ background: 'rgba(245,158,11,0.35)', border: '1px solid var(--primary)' }} /> Detected</span>
        <span className="legend-item"><div className="pie-legend-color" style={{ background: 'rgba(251,146,60,0.30)', border: '1px solid #f97316' }} /> Partial</span>
        <span className="legend-item"><div className="pie-legend-color" style={{ background: 'rgba(239,68,68,0.35)', border: '1px solid var(--danger)' }} /> Not Detected</span>
        <span className="legend-item"><div className="pie-legend-color" style={{ background: 'var(--surface2)', border: '1px solid var(--border)' }} /> No Data</span>
      </div>

      {loading ? <Loading text="Loading coverage data..." /> : (
        <div className="card mitre-card" style={{ padding: '12px' }}>
          <div className="mitre-grid" style={{ gridTemplateColumns: `repeat(${cols}, 1fr)` }}>
            {MITRE_TACTICS.map((tactic, i) => {
              const coverage = getCoverage(tactic);
              const techs = techniquesForTactic(tactic);
              return (
                <div key={i} className={`mitre-cell header coverage-${coverage}`} style={{ gridColumn: `${(i % cols) + 1}`, gridRow: `${Math.floor(i / cols) + 1}` }}
                  onClick={() => setSelectedTactic(selectedTactic === tactic ? null : tactic)}>
                  <div className="mitre-tactic-name">{tactic}</div>
                  <div className="mitre-tactic-count">{techs.length} techniques</div>
                </div>
              );
            })}
          </div>

          {selectedTactic && (
            <div className="mt-24">
              <h4 className="card-title" style={{ marginBottom: '12px' }}>
                <span className="card-title-kicker">tactic drill-down</span>
                {selectedTactic} - Techniques
              </h4>
              <div className="grid grid-3 mitre-tiles" style={{ gap: '8px' }}>
                {techniquesForTactic(selectedTactic).map((tech, i) => {
                  const techAlerts = getTechniqueAlerts(tech.id);
                  const coverage = techAlerts.length > 0 ? getCoverage(selectedTactic) : 'none';
                  return (
                    <div key={i} className={`mitre-cell mitre-tile ${coverage}`}
                      style={{ justifyContent: 'flex-start', textAlign: 'left', padding: '10px 12px', minHeight: 'auto' }}
                      title={`${tech.id}: ${tech.name}`}>
                      <span className="mitre-tile-dot" />
                      <div>
                        <div className="mitre-tile-id mono">{tech.id}</div>
                        <div className="mitre-tile-name">{tech.name}</div>
                        <div className="mitre-tile-alerts">{techAlerts.length} alerts</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {!selectedTactic && (
            <div className="mt-24">
              <div className="card-title">Technique Coverage Summary</div>
              <EmptyState icon="&#x1F52C;" text="Click a tactic column to view its techniques and detection coverage" />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============ APP ============
export default function App() {
  const [page, setPage] = useState('/');
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('theme') || 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);
  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [agents, setAgents] = useState([]);
  const [toasts, setToasts] = useState([]);
  const [agent, setAgent] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const wsAlertsRef = useRef(null);
  const wsAgentsRef = useRef(null);

  const addToast = useCallback((message, type = 'info') => {
    const id = randomId();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // 1. Map each page to a specific 3D rotation angle
  const pageRotations = {
    '/': 'rotateX(-15deg) rotateY(45deg)',
    '/agents': 'rotateX(20deg) rotateY(135deg)',
    '/alerts': 'rotateX(-10deg) rotateY(225deg)',
    '/threats': 'rotateX(25deg) rotateY(315deg)',
    '/settings': 'rotateX(-25deg) rotateY(90deg)',
    '/mitre': 'rotateX(15deg) rotateY(180deg)'
  };

  // 2. Get the current rotation based on the active page
  const currentRotation = pageRotations[page] || pageRotations['/'];

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  // Check for existing auth token on mount
  useEffect(() => {
    const token = getAuthToken();
    if (!token) { setAuthLoading(false); return; }
    apiFetch('/auth/me').then((user) => {
      setAgent(user);
      setAuthLoading(false);
    }).catch(() => {
      setAuthToken(null);
      setAuthLoading(false);
    });
  }, []);

  // Load data when authenticated
  useEffect(() => {
    if (!agent) return;
    apiFetch('/alerts').then(data => {
      const raw = Array.isArray(data) ? data : (data.alerts || []);
      setAlerts(raw.map(normalizeAlert));
    }).catch(() => { });

    apiFetch('/agents').then(data => {
      const raw = Array.isArray(data) ? data : (data.agents || []);
      setAgents(raw.map(normalizeAgent));
    }).catch(() => { });
  }, [agent]);

  useEffect(() => {
    if (!agent) return;
    function connectWebSocket(url, onMessage, setConnectedState) {
      let ws;
      try {
        ws = new WebSocket(url);
      } catch (e) { return null; }

      ws.onopen = () => { setConnectedState(true); };
      ws.onclose = () => { setConnectedState(false); };
      ws.onerror = () => { setConnectedState(false); };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onMessage(data);
        } catch (e) { }
      };
      return ws;
    }

    const wsAlert = connectWebSocket(
      `ws://${window.location.host}/ws/alerts`,
      (data) => {
        if (data.type === 'alert' || data.action === 'new') {
          setAlerts(prev => [data.alert || data, ...prev].slice(0, 200));
          addToast(`New alert: ${(data.alert || data).description || (data.alert || data).type || 'Unknown'}`, 'alert');
        }
      },
      setConnected
    );
    wsAlertsRef.current = wsAlert;

    const wsAgent = connectWebSocket(
      `ws://${window.location.host}/ws/agents`,
      (data) => {
        if (data.type === 'update' || data.action === 'status') {
          setAgents(prev => {
            const updated = data.agent || data;
            const idx = prev.findIndex(a => (a.id || a.agentId) === (updated.id || updated.agentId));
            if (idx >= 0) {
              const next = [...prev];
              next[idx] = { ...next[idx], ...updated };
              return next;
            }
            return [updated, ...prev];
          });
        }
      },
      () => { }
    );
    wsAgentsRef.current = wsAgent;

    return () => {
      if (wsAlertsRef.current) wsAlertsRef.current.close();
      if (wsAgentsRef.current) wsAgentsRef.current.close();
    };
  }, [addToast, agent]);

  const renderPage = () => {
    switch (page) {
      case '/': return <Dashboard alerts={alerts} agents={agents} onNavigate={setPage} />;
      case '/agents': return <Agents onNavigate={setPage} />;
      case '/alerts': return <Alerts />;
      case '/threats': return <ThreatMap />;
      case '/settings': return <Settings />;
      case '/mitre': return <MitreMatrix />;
      default: return <Dashboard alerts={alerts} agents={agents} onNavigate={setPage} />;
    }
  };

  if (authLoading) {
    return <div className="boot-screen" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: 'var(--bg)', color: 'var(--text2)', gap: '16px' }}>
      <div className="boot-shield">&#x1F6E1;&#xFE0F;</div>
      <div className="boot-bar"><div className="boot-bar-fill" /></div>
      <span className="mono">INITIALIZING SECURE CHANNEL...</span>
    </div>;
  }

  if (!agent) {
    return <AuthPage onAuth={(a) => setAgent(a)} theme={theme} toggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} />;
  }

  return (
    <div className="app-layout">
      <div className="app-grid" aria-hidden="true" />

      {/* NEW: Permanent Interactive Background Cube (Dense Glowing Voxel Effect) */}
      <div className="background-cyber-cube-wrapper">
        <div className="background-cyber-cube" style={{ transform: currentRotation }}>
          
          {/* Massive Glowing Inner Core */}
          <div className="cyber-cube-core">
          </div>

          {/* Inner Lattice (Adds density and complexity) */}
          <div className="inner-lattice">
            <div className="face front"></div><div className="face back"></div>
            <div className="face right"></div><div className="face left"></div>
            <div className="face top"></div><div className="face bottom"></div>
          </div>
          
          {/* Main Outer Shell (Heavily fractured and glowing) */}
          <div className="main-shell">
            <div className="face front"></div><div className="face back"></div>
            <div className="face right"></div><div className="face left"></div>
            <div className="face top"></div><div className="face bottom"></div>
          </div>

          {/* Dense Voxel Fragments clustering and breaking away (Now 40 fragments!) */}
          {[...Array(40)].map((_, i) => (
            <div key={i} className={`fragment frag-${i + 1}`}>
              <div className="ff front"></div><div className="ff back"></div>
              <div className="ff right"></div><div className="ff left"></div>
              <div className="ff top"></div><div className="ff bottom"></div>
            </div>
          ))}
          
        </div>
      </div>

      <Sidebar page={page} navigate={setPage} connected={connected} userEmail={agent?.email} onLogout={() => { setAuthToken(null); setAgent(null); window.location.reload(); }} theme={theme} toggleTheme={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} />
      <div className="app-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <span className="crumb root">SOC Console</span>
            <span className="crumb-sep">/</span>
            <span className="crumb current">{(() => { const c = NAV.find(n => n.path === page); return c ? c.label : 'Dashboard'; })()}</span>
          </div>
          <div className="topbar-right">
            <div className="soc-status">
              <span className={`live-dot ${connected ? 'live' : 'down'}`} />
              <span>{connected ? 'SOC Operational' : 'SOC DEGRADED'}</span>
              <span className="soc-live-tag">LIVE</span>
            </div>
            <div className="user-badge">
              <span className="user-avatar">{(() => { const e = agent?.email; return e ? e.charAt(0).toUpperCase() : 'U'; })()}</span>
              <span className="user-email">{agent?.email || 'Operator'}</span>
            </div>
          </div>
        </header>
        <main className="main-content">
          <div className="page-view" key={page}>{renderPage()}</div>
        </main>
      </div>
      
      
      <Toast toasts={toasts} removeToast={removeToast} />
    </div>
  );
}