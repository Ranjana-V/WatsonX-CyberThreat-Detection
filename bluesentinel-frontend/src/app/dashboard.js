"use client";

import React, { useEffect, useState } from "react";
import { AlertTriangle, Shield, Activity, Globe, Clock, Eye, EyeOff, TrendingUp, Server, Database, Cloud } from "lucide-react";

function AlertDashboard() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [blockedIps, setBlockedIps] = useState([]);
  const [query, setQuery] = useState("");
  const [response, setResponse] = useState("");
  const [loading, setLoading] = useState(false);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [showAllAlerts, setShowAllAlerts] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const fetchAlerts = async () => {
    try {
      const res = await fetch("http://localhost:8000/alerts");
      const data = await res.json();
      setAlerts(data.alerts);
    } catch (err) {
      console.error("Error fetching alerts", err);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch("http://localhost:8000/stats");
      const data = await res.json();
      setStats(data);
    } catch (err) {
      console.error("Error fetching stats", err);
    }
  };

  const fetchBlockedIps = async () => {
    try {
      const res = await fetch("http://localhost:8000/blocked_ips");
      const data = await res.json();
      setBlockedIps(data.blocked_ips);
    } catch (err) {
      console.error("Error fetching blocked IPs", err);
    }
  };

  const handleAsk = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query })
      });
      const data = await res.json();
      setResponse(data.answer || data.error);
    } catch (err) {
      setResponse("Error communicating with WatsonX AI.");
    }
    setLoading(false);
  };

  const simulateLogs = async () => {
  setSimulationLoading(true);
  setIsSimulating(true);
  try {
    // Start the simulation
    const res = await fetch("http://localhost:8000/simulate_logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    setResponse(`✅ ${data.message}`);
    
    // Start real-time polling for updates
    const pollInterval = setInterval(async () => {
      try {
        const statusRes = await fetch("http://localhost:8000/processing_status");
        const statusData = await statusRes.json();
        
        // Update all data in real-time
        await fetchAlerts();
        await fetchStats();
        await fetchBlockedIps();
        
        // Check if we should stop polling (no new updates for a while)
        // You can add logic here to stop polling after some time
        
      } catch (err) {
        console.error("Error polling status", err);
      }
    }, 1000); // Poll every 1 second
    
    // Stop polling after 30 seconds (adjust as needed)
    setTimeout(() => {
      clearInterval(pollInterval);
      setIsSimulating(false);
      setSimulationLoading(false);
    }, 30000);
    
  } catch (err) {
    setResponse("❌ Error starting log simulation.");
    setIsSimulating(false);
    setSimulationLoading(false);
  }
};

  const unblockIp = async (ip) => {
    try {
      const res = await fetch("http://localhost:8000/unblock_ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      await fetchBlockedIps();
      setResponse(`✅ IP ${ip} has been unblocked.`);
    } catch (err) {
      setResponse(`❌ Error unblocking IP ${ip}.`);
    }
  };

  const smartQuestions = [
    "What are the most critical threats right now?",
    "Should I be concerned about any recent activities?",
    "What remediation steps do you recommend?",
    "Are there any compliance violations?",
    "Which IPs are causing the most problems?",
    "How is our overall security posture?"
  ];

  useEffect(() => {
  fetchAlerts();
  fetchStats();
  fetchBlockedIps();
  
  // Only set up regular interval if not actively simulating
  const interval = setInterval(() => {
    if (!isSimulating) {
      fetchAlerts();
      fetchStats();
      fetchBlockedIps();
    }
  }, 5000); // Slower refresh when not simulating
  
  return () => clearInterval(interval);
}, [isSimulating]);

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "#dc2626";
      case "high": return "#ea580c";
      case "medium": return "#d97706";
      case "low": return "#65a30d";
      default: return "#6b7280";
    }
  };

  const getSeverityBg = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "#fef2f2";
      case "high": return "#fff7ed";
      case "medium": return "#fffbeb";
      case "low": return "#f7fee7";
      default: return "#f9fafb";
    }
  };

  const getThreatIcon = (threatType) => {
    switch (threatType) {
      case "malware": return "🦠";
      case "data_exfiltration": return "📤";
      case "privilege_escalation": return "⬆️";
      case "brute_force": return "🔨";
      case "sql_injection": return "💉";
      case "ddos": return "🌊";
      case "compliance_violation": return "⚖️";
      case "anomaly": return "📊";
      default: return "🚨";
    }
  };

  const flagEmoji = (geo) => {
    if (geo?.includes("India")) return "🇮🇳";
    if (geo?.includes("USA")) return "🇺🇸";
    if (geo?.includes("Tor")) return "🧅";
    if (geo?.includes("Asia")) return "🌏";
    if (geo?.includes("Internal")) return "🏢";
    return "🌐";
  };

  const displayedAlerts = showAllAlerts ? alerts : alerts.slice(0, 10);

  return (
    <div className="min-h-screen bg-gray-50 font-sans">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900 to-purple-800 text-white p-6 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8" />
            <div>
              <h1 className="text-3xl font-bold">BlueSentinel+.AI</h1>
              <p className="text-blue-200">Advanced IBM Cloud Threat Detection & Compliance Platform</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={simulateLogs}
              disabled={simulationLoading}
              className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors"
            >
              {simulationLoading ? (
                <>
                    <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full"></div>
                    <span>{isSimulating ? "Processing Logs..." : "Starting..."}</span>
                </>
                ) : (
                <>
                    <Activity className="w-4 h-4" />
                    <span>Simulate IBM Logs</span>
                </>
                )}
            </button>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Statistics Dashboard */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white p-6 rounded-lg shadow-md border-l-4 border-red-500">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-gray-500 text-sm">Total Alerts</h3>
                <p className="text-3xl font-bold text-gray-900">{stats.total_alerts || 0}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md border-l-4 border-orange-500">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-gray-500 text-sm">Blocked IPs</h3>
                <p className="text-3xl font-bold text-gray-900">{stats.blocked_ips || 0}</p>
              </div>
              <Eye className="w-8 h-8 text-orange-500" />
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md border-l-4 border-blue-500">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-gray-500 text-sm">Avg Confidence</h3>
                <p className="text-3xl font-bold text-gray-900">{(stats.average_confidence * 100)?.toFixed(1) || 0}%</p>
              </div>
              <TrendingUp className="w-8 h-8 text-blue-500" />
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow-md border-l-4 border-green-500">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-gray-500 text-sm">Critical Alerts</h3>
                <p className="text-3xl font-bold text-gray-900">{stats.severity_breakdown?.critical || 0}</p>
              </div>
              <Server className="w-8 h-8 text-green-500" />
            </div>
          </div>
        </div>

        {/* Threat Type Breakdown */}
        {stats.threat_types && Object.keys(stats.threat_types).length > 0 && (
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <Database className="w-5 h-5 mr-2" />
              Threat Type Distribution
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(stats.threat_types).map(([type, count]) => (
                <div key={type} className="text-center p-3 bg-gray-50 rounded-lg">
                  <div className="text-2xl mb-1">{getThreatIcon(type)}</div>
                  <div className="font-semibold">{count}</div>
                  <div className="text-sm text-gray-600 capitalize">{type.replace(/_/g, ' ')}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* AI Query Interface */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-bold mb-4 flex items-center">
            <Cloud className="w-5 h-5 mr-2" />
            Ask WatsonX AI
          </h2>
          
          <div className="flex space-x-3 mb-4">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask about your security posture, threats, or get recommendations..."
              className="flex-1 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              onKeyPress={(e) => e.key === 'Enter' && handleAsk()}
            />
            <button
              onClick={handleAsk}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg flex items-center space-x-2 transition-colors disabled:opacity-50"
            >
              {loading ? (
                <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full"></div>
              ) : (
                <Activity className="w-4 h-4" />
              )}
              <span>Ask</span>
            </button>
          </div>

          {response && (
            <div className="bg-blue-50 border border-blue-200 p-4 rounded-lg">
              <h4 className="font-semibold text-blue-900 mb-2">🤖 WatsonX Analysis:</h4>
              <p className="text-blue-800 whitespace-pre-wrap">{response}</p>
            </div>
          )}

          <div className="mt-4">
            <h4 className="font-semibold text-gray-700 mb-2">💡 Quick Questions:</h4>
            <div className="flex flex-wrap gap-2">
              {smartQuestions.map((q, i) => (
                <button
                  key={i}
                  onClick={() => { setQuery(q); handleAsk(); }}
                  className="text-sm bg-gray-100 hover:bg-gray-200 px-3 py-1 rounded-full transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Live Alert Ticker */}
        {alerts.length > 0 && (
          <div className="bg-gradient-to-r from-red-100 to-orange-100 p-4 rounded-lg shadow-md overflow-hidden">
            <h3 className="font-semibold mb-2 flex items-center">
              <Activity className="w-4 h-4 mr-2" />
              Live Threat Feed
            </h3>
            <div className="whitespace-nowrap animate-marquee">
              {alerts.slice(-10).map((alert, i) => (
                <span key={i} className="inline-block mr-8 font-medium">
                  {getThreatIcon(alert.threat_type)} 
                  <span className="ml-2" style={{ color: getSeverityColor(alert.severity) }}>
                    {alert.severity?.toUpperCase()} - {alert.threat_type?.toUpperCase()}
                  </span>
                  <span className="ml-2 text-gray-600">from {alert.source_ip}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Blocked IPs */}
        {blockedIps.length > 0 && (
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <EyeOff className="w-5 h-5 mr-2" />
              Blocked IP Addresses ({blockedIps.length})
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {blockedIps.map((ipData, idx) => (
                <div key={idx} className="bg-red-50 border border-red-200 p-4 rounded-lg">
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-mono font-bold text-red-800">{ipData.ip}</div>
                    <button
                      onClick={() => unblockIp(ipData.ip)}
                      className="text-xs bg-red-600 hover:bg-red-700 text-white px-2 py-1 rounded transition-colors"
                    >
                      Unblock
                    </button>
                  </div>
                  <div className="text-sm space-y-1">
                    <div>{flagEmoji(ipData.geo_location)} {ipData.geo_location}</div>
                    <div>Alerts: {ipData.alert_count}</div>
                    <div>Threats: {ipData.threat_types.join(', ')}</div>
                    <div className="text-gray-600">Last: {ipData.last_seen}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Alerts Feed */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold flex items-center">
              <Globe className="w-5 h-5 mr-2" />
              Security Alerts Feed
            </h2>
            {alerts.length > 10 && (
              <button
                onClick={() => setShowAllAlerts(!showAllAlerts)}
                className="text-blue-600 hover:text-blue-800 flex items-center space-x-1"
              >
                <Eye className="w-4 h-4" />
                <span>{showAllAlerts ? 'Show Less' : `Show All (${alerts.length})`}</span>
              </button>
            )}
          </div>

          <div className="space-y-3 max-h-96 overflow-y-auto">
            {displayedAlerts.map((alert, idx) => (
              <div
                key={idx}
                className="border rounded-lg p-4 transition-all hover:shadow-md"
                style={{
                  backgroundColor: getSeverityBg(alert.severity),
                  borderLeftColor: getSeverityColor(alert.severity),
                  borderLeftWidth: '4px'
                }}
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-lg">{getThreatIcon(alert.threat_type)}</span>
                    <span className="font-bold" style={{ color: getSeverityColor(alert.severity) }}>
                      {alert.severity?.toUpperCase()} - {alert.threat_type?.toUpperCase()}
                    </span>
                    {alert.blocked && <span className="bg-red-600 text-white px-2 py-1 rounded text-xs">BLOCKED</span>}
                  </div>
                  <div className="text-xs text-gray-500 flex items-center">
                    <Clock className="w-3 h-3 mr-1" />
                    {alert.timestamp}
                  </div>
                </div>

                <div className="text-gray-700 mb-2">{alert.message}</div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-sm">
                  <div><strong>Source:</strong> {alert.source}</div>
                  <div><strong>IP:</strong> {alert.source_ip} {flagEmoji(alert.geo_location)}</div>
                  <div><strong>Confidence:</strong> {(alert.confidence_score * 100)?.toFixed(1)}%</div>
                </div>

                {alert.remediation && (
                  <div className="mt-3 p-3 bg-blue-50 rounded border border-blue-200">
                    <strong className="text-blue-800">🔧 Recommended Action:</strong>
                    <p className="text-blue-700 mt-1">{alert.remediation}</p>
                  </div>
                )}
              </div>
            ))}
          </div>

          {alerts.length === 0 && (
            <div className="text-center py-8 text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No security alerts detected. Click "Simulate IBM Logs" to generate sample data.</p>
            </div>
          )}
        </div>
      </div>

      <style jsx>{`
        @keyframes marquee {
          0% { transform: translateX(100%); }
          100% { transform: translateX(-100%); }
        }
        .animate-marquee {
          animation: marquee 30s linear infinite;
        }
      `}</style>
    </div>
  );
}

export default AlertDashboard;