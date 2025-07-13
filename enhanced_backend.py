from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import datetime
import json
import os
import re
import asyncio
import random
from typing import List, Dict, Any
from ibm_watsonx_ai.metanames import GenTextParamsMetaNames as GenParams
from ibm_watsonx_ai.foundation_models import ModelInference
from dotenv import load_dotenv

# WatsonX model configuration
load_dotenv()

watsonx_model = ModelInference(
    model_id="ibm/granite-13b-instruct-v2",
    project_id=os.getenv("WATSONX_PROJECT_ID"),
    credentials={
        "apikey": os.getenv("WATSONX_API_KEY"),
        "url": os.getenv("WATSONX_URL")
    }
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global storage
alerts = []
benign_logs = []  # New: Store benign logs
blocked_ips = set()
processed_logs = set()  # Track processed log IDs to avoid duplicates
threat_patterns = {}  # Store learned threat patterns

class Alert(BaseModel):
    id: str
    source: str
    message: str
    timestamp: str
    threat_type: str
    severity: str
    source_ip: str
    geo_location: str = "Unknown"
    blocked: bool = False
    remediation: str = ""
    confidence_score: float = 0.0
    raw_log: dict = {}

class BenignLog(BaseModel):
    id: str
    source: str
    message: str
    timestamp: str
    source_ip: str
    geo_location: str = "Unknown"
    confidence_score: float = 0.0
    raw_log: dict = {}
    log_type: str = ""

class ThreatAnalysis(BaseModel):
    is_threat: bool
    threat_type: str
    severity: str
    confidence_score: float
    remediation: str
    reasoning: str

def load_mock_logs():
    """Load mock logs from JSON file"""
    try:
        with open('ibm_cloud_mock_logs.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("Warning: ibm_cloud_mock_logs.json not found. Using empty logs.")
        return {
            "logdna_logs": [],
            "activity_tracker_logs": [],
            "monitoring_metrics": [],
            "security_events": [],
            "compliance_violations": []
        }

def extract_ip_from_log(log_entry: dict, log_type: str) -> str:
    """Extract IP address from different log types"""
    if log_type == "logdna":
        return log_entry.get("meta", {}).get("source_ip", "unknown")
    elif log_type == "activity_tracker":
        return log_entry.get("requestData", {}).get("source_ip", "unknown")
    elif log_type == "security_events":
        return log_entry.get("details", {}).get("source_ip", "unknown")
    return "unknown"

def determine_geo_location(ip: str) -> str:
    """Simple geo-location based on IP patterns"""
    if ip.startswith("192.168") or ip.startswith("10.0"):
        return "Internal Network"
    elif ip.startswith("185.220"):
        return "Tor Exit Node"
    elif ip.startswith("203.0"):
        return "Asia Pacific"
    elif ip.startswith("103."):
        return "India"
    else:
        return "Unknown"

async def analyze_log_with_watsonx(log_entry: dict, log_type: str) -> ThreatAnalysis:
    """Use WatsonX to analyze individual log entries for threats"""
    
    # Create a focused prompt for threat analysis
    log_context = json.dumps(log_entry, indent=2)
    
    prompt = f"""
You are an expert cybersecurity analyst. Analyze this {log_type} log entry for potential security threats.

Log Entry:
{log_context}

Analyze this log and respond with a JSON object containing:
{{
    "is_threat": true/false,
    "threat_type": "one of: malware, data_exfiltration, privilege_escalation, brute_force, sql_injection, ddos, compliance_violation, anomaly, benign",
    "severity": "one of: low, medium, high, critical",
    "confidence_score": 0.0-1.0,
    "remediation": "specific remediation steps",
    "reasoning": "brief explanation of the analysis"
}}

Focus on indicators like:
- Unusual access patterns
- Failed authentication attempts
- Privilege escalation
- Data access anomalies
- Network traffic patterns
- Compliance violations
- Suspicious file operations
"""

    try:
        response = watsonx_model.generate(
            prompt=prompt,
            params={
                GenParams.DECODING_METHOD: "greedy",
                GenParams.MAX_NEW_TOKENS: 400,
                GenParams.TEMPERATURE: 0.1
            }
        )
        
        raw_response = response["results"][0]["generated_text"]
        
        # Extract JSON from response
        json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
        if json_match:
            try:
                analysis_data = json.loads(json_match.group())
                return ThreatAnalysis(**analysis_data)
            except json.JSONDecodeError:
                pass
        
        # Fallback analysis if WatsonX doesn't return proper JSON
        return fallback_threat_analysis(log_entry, log_type)
        
    except Exception as e:
        print(f"WatsonX analysis failed: {e}")
        return fallback_threat_analysis(log_entry, log_type)

def fallback_threat_analysis(log_entry: dict, log_type: str) -> ThreatAnalysis:
    """Fallback rule-based threat analysis"""
    is_threat = False
    threat_type = "benign"
    severity = "low"
    confidence_score = 0.5
    remediation = "No action required"
    reasoning = "Standard log entry"
    
    # Rule-based detection patterns
    if log_type == "logdna":
        line = log_entry.get("line", "").lower()
        level = log_entry.get("level", "")
        
        if "failed login" in line or "authentication failed" in line:
            is_threat = True
            threat_type = "brute_force"
            severity = "medium"
            confidence_score = 0.8
            remediation = "Monitor source IP, implement rate limiting, consider IP blocking"
            reasoning = "Multiple failed authentication attempts detected"
        elif "sql" in line and ("select * from" in line or "drop table" in line):
            is_threat = True
            threat_type = "sql_injection"
            severity = "high"
            confidence_score = 0.9
            remediation = "Block malicious queries, review input validation, audit database access"
            reasoning = "Potential SQL injection pattern detected"
        elif level == "CRITICAL" or "unauthorized" in line:
            is_threat = True
            threat_type = "anomaly"
            severity = "high"
            confidence_score = 0.7
            remediation = "Investigate immediately, review access controls"
            reasoning = "Critical security event detected"
    
    elif log_type == "activity_tracker":
        action = log_entry.get("action", "")
        outcome = log_entry.get("outcome", "")
        
        if "delete" in action and outcome == "success":
            is_threat = True
            threat_type = "data_exfiltration"
            severity = "medium"
            confidence_score = 0.6
            remediation = "Review deletion policies, implement backup verification"
            reasoning = "Sensitive data deletion detected"
        elif "policy.create" in action and "Administrator" in str(log_entry.get("requestData", {})):
            is_threat = True
            threat_type = "privilege_escalation"
            severity = "high"
            confidence_score = 0.8
            remediation = "Review policy changes, verify authorization, implement approval workflow"
            reasoning = "Administrative privilege granted"
    
    elif log_type == "security_events":
        event_type = log_entry.get("event_type", "")
        severity_map = {"high": "high", "critical": "critical", "medium": "medium"}
        
        is_threat = True
        threat_type = event_type.replace("_", "_")
        severity = severity_map.get(log_entry.get("severity", "medium"), "medium")
        confidence_score = 0.9
        remediation = "Immediate investigation required, follow incident response procedures"
        reasoning = f"Security event: {event_type}"
    
    return ThreatAnalysis(
        is_threat=is_threat,
        threat_type=threat_type,
        severity=severity,
        confidence_score=confidence_score,
        remediation=remediation,
        reasoning=reasoning
    )

async def process_log_entry(log_entry: dict, log_type: str) -> None:
    """Process a single log entry and create alert if threat detected or store as benign"""
    # Generate unique ID based on log content and timestamp
    log_content_hash = hash(json.dumps(log_entry, sort_keys=True))
    log_id = f"{log_type}_{log_entry.get('timestamp', '')}_hash_{log_content_hash}"
    
    # Check if this specific log was already processed (allow reprocessing different logs)
    if log_id in processed_logs:
        return
    
    processed_logs.add(log_id)
    
    # Analyze with WatsonX
    analysis = await analyze_log_with_watsonx(log_entry, log_type)
    
    source_ip = extract_ip_from_log(log_entry, log_type)
    geo_location = determine_geo_location(source_ip)
    
    if analysis.is_threat:
        # Check if IP should be blocked
        ip_alert_count = sum(1 for a in alerts if a["source_ip"] == source_ip)
        blocked = False
        if ip_alert_count >= 2:  # Lower threshold for blocking
            blocked_ips.add(source_ip)
            blocked = True
        
        alert = Alert(
            id=f"alert_{len(alerts) + 1}",
            source=f"IBM Cloud {log_type.replace('_', ' ').title()}",
            message=analysis.reasoning,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            threat_type=analysis.threat_type,
            severity=analysis.severity,
            source_ip=source_ip,
            geo_location=geo_location,
            blocked=blocked,
            remediation=analysis.remediation,
            confidence_score=analysis.confidence_score,
            raw_log=log_entry
        )
        
        alerts.append(alert.dict())
    else:
        # Store benign logs
        benign_log = BenignLog(
            id=f"benign_{len(benign_logs) + 1}",
            source=f"IBM Cloud {log_type.replace('_', ' ').title()}",
            message=analysis.reasoning,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source_ip=source_ip,
            geo_location=geo_location,
            confidence_score=analysis.confidence_score,
            raw_log=log_entry,
            log_type=log_type
        )
        
        benign_logs.append(benign_log.dict())

@app.get("/alerts")
def get_alerts():
    """Get all alerts with enhanced filtering"""
    return {"alerts": sorted(alerts, key=lambda x: x["timestamp"], reverse=True)}

@app.get("/benign_logs")
def get_benign_logs():
    """Get all benign logs"""
    return {"benign_logs": sorted(benign_logs, key=lambda x: x["timestamp"], reverse=True)}

@app.get("/stats")
def get_stats():
    """Enhanced statistics including severity breakdown and benign logs"""
    total = len(alerts)
    total_benign = len(benign_logs)
    
    # Count by threat type
    threat_counts = {}
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    
    for alert in alerts:
        threat_type = alert.get("threat_type", "unknown")
        severity = alert.get("severity", "low")
        
        threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        severity_counts[severity] += 1
    
    blocked = len([a for a in alerts if a.get("blocked")])
    avg_confidence = sum(a.get("confidence_score", 0) for a in alerts) / max(total, 1)
    
    # Benign logs statistics
    benign_by_source = {}
    benign_by_type = {}
    for log in benign_logs:
        source = log.get("source", "unknown")
        log_type = log.get("log_type", "unknown")
        benign_by_source[source] = benign_by_source.get(source, 0) + 1
        benign_by_type[log_type] = benign_by_type.get(log_type, 0) + 1
    
    return {
        "total_alerts": total,
        "total_benign_logs": total_benign,
        "blocked_ips": len(blocked_ips),
        "threat_types": threat_counts,
        "severity_breakdown": severity_counts,
        "average_confidence": round(avg_confidence, 2),
        "blocked_count": blocked,
        "benign_by_source": benign_by_source,
        "benign_by_type": benign_by_type,
        "total_processed_logs": total + total_benign
    }

@app.post("/simulate_logs")
async def simulate_logs():
    """Start streaming simulation of IBM Cloud logs"""
    processed_logs.clear()  
    mock_logs = load_mock_logs()
    
    # Return immediately to start the process
    asyncio.create_task(process_logs_streaming(mock_logs))
    
    return {
        "status": "Log processing started",
        "message": "Logs will be processed in real-time. Check alerts endpoint for updates."
    }

async def process_logs_streaming(mock_logs):
    """Process logs one by one with delays for real-time effect"""
    for log_type, logs in mock_logs.items():
        for log_entry in logs:
            await process_log_entry(log_entry, log_type)
            # Add a small delay to make the processing visible
            await asyncio.sleep(0.5)  # Adjust delay as needed (0.5 seconds between each log)

@app.get("/processing_status")
def get_processing_status():
    """Get real-time processing status"""
    return {
        "total_alerts": len(alerts),
        "total_benign_logs": len(benign_logs),
        "total_processed": len(processed_logs),
        "blocked_ips": len(blocked_ips),
        "last_alert": alerts[-1] if alerts else None,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }            
@app.post("/analyze")
async def analyze(event: dict):
    """Legacy endpoint - enhanced to use WatsonX analysis"""
    # Convert legacy format to log format
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "meta": {"source_ip": event.get("source_ip", "")},
        "line": f"CPU: {event.get('cpu_usage', 0)}%, Login failures: {event.get('login_failures', 0)}",
        "level": "WARN" if event.get("cpu_usage", 0) > 80 else "INFO"
    }
    
    analysis = await analyze_log_with_watsonx(log_entry, "logdna")
    
    if analysis.is_threat:
        source_ip = event.get("source_ip", "")
        alert = Alert(
            id=f"alert_{len(alerts) + 1}",
            source="Legacy API",
            message=analysis.reasoning,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            threat_type=analysis.threat_type,
            severity=analysis.severity,
            source_ip=source_ip,
            geo_location=determine_geo_location(source_ip),
            blocked=source_ip in blocked_ips,
            remediation=analysis.remediation,
            confidence_score=analysis.confidence_score,
            raw_log=log_entry
        )
        alerts.append(alert.dict())
        return {"status": "THREAT DETECTED", "alert": alert.dict(), "analysis": analysis.dict()}
    
    return {"status": "Safe", "analysis": analysis.dict()}

@app.post("/ask")
async def ask_query(req: Request):
    """Enhanced query endpoint with better context and benign logs support"""
    body = await req.json()
    question = body.get("query", "").strip().lower()
    
    # Enhanced statistics
    stats = get_stats()
    
    # Get recent high-severity alerts
    recent_critical = [a for a in alerts if a.get("severity") in ["high", "critical"]][-10:]
    
    # Get recent benign logs
    recent_benign = benign_logs[-10:] if benign_logs else []
    
    # Analyze IPs causing most problems
    ip_problem_analysis = {}
    for alert in alerts:
        ip = alert.get("source_ip", "unknown")
        if ip != "unknown":
            if ip not in ip_problem_analysis:
                ip_problem_analysis[ip] = {
                    "total_alerts": 0,
                    "threat_types": set(),
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "last_seen": alert["timestamp"],
                    "geo_location": alert.get("geo_location", "Unknown"),
                    "blocked": alert.get("blocked", False)
                }
            
            ip_problem_analysis[ip]["total_alerts"] += 1
            ip_problem_analysis[ip]["threat_types"].add(alert.get("threat_type", "unknown"))
            ip_problem_analysis[ip]["severity_counts"][alert.get("severity", "low")] += 1
            if alert["timestamp"] > ip_problem_analysis[ip]["last_seen"]:
                ip_problem_analysis[ip]["last_seen"] = alert["timestamp"]
    
    # Sort IPs by problem severity (weighted score)
    def calculate_ip_threat_score(ip_data):
        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        score = sum(count * weight for severity, weight in severity_weights.items() 
                   for count in [ip_data["severity_counts"][severity]])
        return score
    
    top_problem_ips = sorted(ip_problem_analysis.items(), 
                            key=lambda x: calculate_ip_threat_score(x[1]), 
                            reverse=True)[:5]
    
    # Find compliance-related alerts
    compliance_alerts = []
    for alert in alerts:
        if ("compliance" in alert.get("threat_type", "").lower() or 
            "compliance" in alert.get("message", "").lower() or
            "violation" in alert.get("message", "").lower() or
            "policy" in alert.get("message", "").lower()):
            compliance_alerts.append(alert)
    
    # Build context based on question type
    if "benign" in question or ("safe" in question and "log" in question):
        # Question about benign logs
        benign_details = ""
        if recent_benign:
            for i, log in enumerate(recent_benign, 1):
                raw_log_summary = ""
                if log.get("raw_log"):
                    raw_log = log["raw_log"]
                    if isinstance(raw_log, dict):
                        key_fields = []
                        for key in ["action", "outcome", "requestData", "line", "level", "event_type"]:
                            if key in raw_log and raw_log[key]:
                                key_fields.append(f"{key}: {raw_log[key]}")
                        raw_log_summary = " | ".join(key_fields[:3])
                
                benign_details += f"""{i}. Log ID: {log["id"]}
   - Timestamp: {log["timestamp"]}
   - Source: {log["source"]}
   - Message: {log["message"]}
   - Source IP: {log["source_ip"]}
   - Location: {log["geo_location"]}
   - Log Type: {log["log_type"]}
   - Confidence: {log.get("confidence_score", 0):.2f}
   - Log Details: {raw_log_summary}

"""
        else:
            benign_details = "No benign logs recorded yet."
        
        context = f"""
BENIGN (SAFE) LOGS ANALYSIS:

{benign_details}

BENIGN LOGS SUMMARY:
- Total Benign Logs: {stats['total_benign_logs']}
- Benign Logs by Source: {json.dumps(stats['benign_by_source'], indent=2)}
- Benign Logs by Type: {json.dumps(stats['benign_by_type'], indent=2)}

OVERALL SYSTEM STATUS:
- Total Processed Logs: {stats['total_processed_logs']}
- Threat Alerts: {stats['total_alerts']}
- Safe/Benign Logs: {stats['total_benign_logs']}
- Blocked IPs: {stats['blocked_ips']}
"""
        
        prompt = f"""You are BlueSentinel+.AI cybersecurity analyst.

BENIGN LOGS SUMMARY:
- Total safe logs: {stats['total_benign_logs']}
- Sources: {list(stats['benign_by_source'].keys())}
- Types: {list(stats['benign_by_type'].keys())}

USER QUESTION: {question}

Provide a brief analysis of the benign logs. Stop after answering the question."""

    elif "ip" in question and ("problem" in question or "causing" in question or "most" in question):
        # Question about problematic IPs (existing code)
        ip_details = ""
        for i, (ip, data) in enumerate(top_problem_ips, 1):
            threat_types_str = ", ".join(list(data["threat_types"]))
            ip_details += f"""{i}. IP: {ip}
   - Location: {data["geo_location"]}
   - Total Alerts: {data["total_alerts"]}
   - Threat Types: {threat_types_str}
   - Severity Breakdown: Critical({data["severity_counts"]["critical"]}), High({data["severity_counts"]["high"]}), Medium({data["severity_counts"]["medium"]}), Low({data["severity_counts"]["low"]})
   - Last Activity: {data["last_seen"]}
   - Status: {"BLOCKED" if data["blocked"] else "ACTIVE"}
   - Threat Score: {calculate_ip_threat_score(data)}

"""
        
        context = f"""
TOP PROBLEMATIC IP ADDRESSES (by threat severity):

{ip_details}

SUMMARY STATISTICS:
- Total Unique IPs with Alerts: {len(ip_problem_analysis)}
- IPs Currently Blocked: {len(blocked_ips)}
- Total Security Events: {stats['total_alerts']}
"""
        
        prompt = f"""
You are BlueSentinel+.AI, analyzing which IP addresses are causing the most security problems.

Based on the data provided, analyze the top problematic IP addresses and provide specific insights about:
1. Which IPs are generating the most alerts
2. What types of threats they're associated with
3. Geographic patterns if any
4. Recommended actions for each IP

Current Data:
{context}

User Question: "{question}"

Provide a detailed analysis focusing specifically on the most problematic IP addresses, including specific IP addresses, their threat scores, and actionable recommendations.
"""

    elif "compliance" in question and ("error" in question or "violation" in question or "log" in question):
        # Question about compliance violations (existing code)
        compliance_details = ""
        if compliance_alerts:
            for i, alert in enumerate(compliance_alerts[:10], 1):
                raw_log_summary = ""
                if alert.get("raw_log"):
                    raw_log = alert["raw_log"]
                    if isinstance(raw_log, dict):
                        key_fields = []
                        for key in ["action", "outcome", "requestData", "line", "level", "event_type"]:
                            if key in raw_log and raw_log[key]:
                                key_fields.append(f"{key}: {raw_log[key]}")
                        raw_log_summary = " | ".join(key_fields[:3])
                
                compliance_details += f"""{i}. Alert ID: {alert["id"]}
   - Timestamp: {alert["timestamp"]}
   - Source: {alert["source"]}
   - Message: {alert["message"]}
   - Threat Type: {alert["threat_type"]}
   - Severity: {alert["severity"]}
   - Source IP: {alert["source_ip"]}
   - Log Details: {raw_log_summary}
   - Remediation: {alert.get("remediation", "N/A")}

"""
        else:
            compliance_details = "No compliance violations detected in current alerts."
        
        context = f"""
COMPLIANCE VIOLATIONS AND RELATED LOGS:

{compliance_details}

COMPLIANCE SUMMARY:
- Total Compliance-Related Alerts: {len(compliance_alerts)}
- Recent Compliance Issues: {len([a for a in compliance_alerts if a.get("severity") in ["high", "critical"]])}
- Sources Generating Compliance Alerts: {list(set([a["source"] for a in compliance_alerts]))}
"""
        
        prompt = f"""
You are BlueSentinel+.AI, analyzing compliance violations and policy breaches.

Based on the compliance-related alerts and logs, provide specific insights about:
1. Which specific logs generated compliance errors
2. What compliance rules or policies were violated
3. The source systems and IP addresses involved
4. Recommended remediation steps

Current Compliance Data:
{context}

User Question: "{question}"

Provide a detailed analysis focusing specifically on compliance violations, including the exact logs that triggered alerts and specific remediation recommendations.
"""

    else:
        # General security question
        alert_summary = "\n".join([
            f"- [{a['timestamp']}] {a['severity'].upper()}: {a['message']} (IP: {a['source_ip']}, Type: {a['threat_type']}, Confidence: {a.get('confidence_score', 0):.2f})"
            for a in recent_critical[:5]
        ]) or "No critical alerts."
        
        benign_summary = "\n".join([
            f"- [{b['timestamp']}] SAFE: {b['message']} (IP: {b['source_ip']}, Type: {b['log_type']}, Confidence: {b.get('confidence_score', 0):.2f})"
            for b in recent_benign[:3]
        ]) or "No benign logs recorded."
        
        context = f"""
SECURITY OVERVIEW:
- Total Alerts: {stats['total_alerts']}
- Total Benign Logs: {stats['total_benign_logs']}
- Blocked IPs: {stats['blocked_ips']}
- Average Confidence: {stats['average_confidence']}

THREAT DISTRIBUTION:
{json.dumps(stats['threat_types'], indent=2)}

SEVERITY BREAKDOWN:
- Critical: {stats['severity_breakdown']['critical']}
- High: {stats['severity_breakdown']['high']}
- Medium: {stats['severity_breakdown']['medium']}
- Low: {stats['severity_breakdown']['low']}

RECENT CRITICAL/HIGH SEVERITY ALERTS:
{alert_summary}

RECENT BENIGN (SAFE) LOGS:
{benign_summary}
"""
        
        prompt = f"""
You are BlueSentinel+.AI, an advanced cybersecurity analyst for IBM Cloud infrastructure.

Analyze the current security landscape and provide expert insights based on real-time threat detection data.

If the question is not related to cybersecurity, respond with: "I specialize in cybersecurity threat analysis. Please ask about threat detection, security monitoring, or cloud security."

Current System Data:
{context}

User Question: "{question}"

Provide specific, actionable cybersecurity insights with concrete recommendations based on the actual data.
"""

    try:
        response = watsonx_model.generate(
            prompt=prompt,
            params={
                GenParams.DECODING_METHOD: "greedy",
                GenParams.MAX_NEW_TOKENS: 600,
                GenParams.TEMPERATURE: 0.1  # Lower temperature for more focused responses
            }
        )
        
        raw_answer = response["results"][0]["generated_text"]
        
        # Clean up formatting
        clean_answer = re.sub(r"\*\*(.*?)\*\*", r"\1", raw_answer)
        clean_answer = re.sub(r"\* ", "- ", clean_answer)
        clean_answer = re.sub(r"`([^`]+)`", r"\1", clean_answer)
        
        return {"answer": clean_answer}
        
    except Exception as e:
        return {"error": f"Analysis service temporarily unavailable: {str(e)}"}

@app.get("/blocked_ips")
def get_blocked_ips():
    """Get list of blocked IPs with details"""
    blocked_details = []
    for ip in blocked_ips:
        ip_alerts = [a for a in alerts if a["source_ip"] == ip]
        blocked_details.append({
            "ip": ip,
            "geo_location": determine_geo_location(ip),
            "alert_count": len(ip_alerts),
            "last_seen": max([a["timestamp"] for a in ip_alerts]) if ip_alerts else "Unknown",
            "threat_types": list(set([a["threat_type"] for a in ip_alerts]))
        })
    
    return {"blocked_ips": blocked_details}

@app.post("/unblock_ip")
def unblock_ip(request: dict):
    """Unblock a specific IP address"""
    ip = request.get("ip")
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        return {"status": "success", "message": f"IP {ip} has been unblocked"}
    return {"status": "error", "message": "IP not found in blocked list"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)