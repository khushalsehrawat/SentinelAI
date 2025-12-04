package com.ai.ThreatDetection.service;

import com.ai.ThreatDetection.entity.Alert;
import com.ai.ThreatDetection.entity.Incident;
import com.ai.ThreatDetection.entity.LogEntry;
import com.ai.ThreatDetection.entity.User;
import com.ai.ThreatDetection.repository.IncidentRepository;
import com.ai.ThreatDetection.repository.LogRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * LogService:
 *  - Saves raw logs
 *  - Calls AIService for enriched analysis (severity, technique, score)
 *  - Updates LogEntry with AI output
 *  - Creates Incident with summary + MITRE + score
 *  - Triggers Alert if severity HIGH/CRITICAL
 *  - Prepares hook for auto-remediation (BLOCK_IP, ISOLATE_HOST)
 */
@Service
public class LogService {

    private final LogRepository logRepository;
    private final IncidentRepository incidentRepository;
    private final AIService aiService;
    private final AlertService alertService;
    private final UserService userService;
    private final CurrentUserService currentUserService;


    // Example: send alerts to this email (can externalize later)
    private static final String ADMIN_ALERT_EMAIL = "your_email@gmail.com";

    // Simple IPv4 regex for demo (for BLOCK_IP suggestions)
    private static final Pattern IP_PATTERN =
            Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    public LogService(LogRepository logRepository,
                      IncidentRepository incidentRepository,
                      AIService aiService,
                      AlertService alertService, UserService userService, CurrentUserService currentUserService) {
        this.logRepository = logRepository;
        this.incidentRepository = incidentRepository;
        this.aiService = aiService;
        this.alertService = alertService;
        this.userService = userService;
        this.currentUserService = currentUserService;
    }

    /**
     * Main orchestration method for new logs:
     *  1) Save raw log
     *  2) Call AIService (Gemini) → full analysis
     *  3) Update LogEntry
     *  4) Create Incident (with summary + MITRE + score)
     *  5) Trigger Alert for HIGH/CRITICAL
     *  6) Optionally trigger auto-remediation hook (logged only)
     */
    public LogEntry saveAndAnalyze(String rawLogData, String source, String title, String userCategory) {

        // 1) Save base log
        LogEntry entry = new LogEntry(rawLogData, source);

        User current = currentUserService.getCurrentUser();
        entry.setUser(current);


        entry.setLogData(rawLogData);  // or setLogData(...) based on your field
        entry.setSource(source);
        entry.setTitle(title);
        entry.setUserCategory(userCategory);


        // 🔥 attach current logged-in user
        entry.setUser(currentUserService.getCurrentUser());

        entry = logRepository.save(entry);

        // 2) AI analysis (advanced)
        Map<String, String> result = aiService.analyzeLog(rawLogData);

        String severity = result.get("severity");
        String category = result.get("category");
        String recommendation = result.get("recommendation");
        String mitre = result.get("mitre_technique");
        String summary = result.get("summary");
        String threatScore = result.get("threat_score");
        String autoAction = result.get("auto_action");

        // 3) Update LogEntry with AI results
        entry.setSeverity(severity);
        entry.setCategory(category);
        entry.setRecommendation(recommendation);
        entry = logRepository.save(entry);

        // 4) Create Incident – embed summary, MITRE, score
        StringBuilder details = new StringBuilder();
        details.append(summary).append("\n")
                .append("Category: ").append(category).append("\n")
                .append("Severity: ").append(severity).append("\n")
                .append("Threat Score: ").append(threatScore).append("/100").append("\n")
                .append("MITRE Technique: ").append(mitre).append("\n")
                .append("Recommendation: ").append(recommendation);

        Incident inc = new Incident(details.toString(), entry);
        inc.setSeverity(severity);
        inc = incidentRepository.save(inc);

        // 5) Alerts for HIGH/CRITICAL
        String sevUpper = severity != null ? severity.toUpperCase() : "LOW";
        if ("HIGH".equals(sevUpper) || "CRITICAL".equals(sevUpper)) {
            String msg = "Incident #" + inc.getId() + " | Severity: " + sevUpper
                    + "\nCategory: " + category
                    + "\nThreat Score: " + threatScore + "/100"
                    + "\nMITRE: " + mitre
                    + "\nRecommendation: " + recommendation;
            Alert alert = alertService.createEmailAlert(inc, sevUpper, msg, ADMIN_ALERT_EMAIL);
            // (no need to use 'alert' further here)
        }

        // 6) Auto-remediation hook (simulated)
        handleAutoAction(autoAction, rawLogData, inc);

        return entry;
    }

    public List<LogEntry> list() {
        if (currentUserService.isAdmin()) {
            // ADMIN sees everything
            return logRepository.findAll();
        }

        // Normal user → only their own logs
        var user = currentUserService.getCurrentUser();
        return logRepository.findByUser(user);
    }

    public LogEntry find(Long id) {
        return logRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Log not found"));
    }

    /**
     * Auto-remediation hook.
     *
     * This DOES NOT execute real system commands now (for safety).
     * Instead, it logs what it *would* do. In a real SOC integration,
     * you would:
     *  - call a firewall API,
     *  - call EDR/XDR API,
     *  - or enqueue a job for SOAR platform.
     */
    private void handleAutoAction(String autoAction, String logData, Incident incident) {
        if (autoAction == null) return;

        String action = autoAction.toUpperCase().trim();
        if ("NONE".equals(action)) {
            return;
        }

        // Try to extract an IP (for BLOCK_IP suggestion)
        String ip = extractFirstIp(logData);

        switch (action) {
            case "BLOCK_IP":
                System.out.println("[AUTO-ACTION] Suggested BLOCK_IP for incident #" + incident.getId()
                        + " on IP: " + ip);
                // Here you could call your firewall API:
                // firewallClient.blockIp(ip);
                break;

            case "ISOLATE_HOST":
                System.out.println("[AUTO-ACTION] Suggested ISOLATE_HOST for incident #" + incident.getId()
                        + ". (You could integrate with EDR/Soar here)");
                break;

            default:
                // Unknown / unsupported auto action
                break;
        }
    }

    private String extractFirstIp(String text) {
        if (text == null) return "N/A";
        Matcher m = IP_PATTERN.matcher(text);
        if (m.find()) {
            return m.group();
        }
        return "N/A";
    }

    public void delete(Long id) {
        // 1) Fetch the log entry (throw if not found)
        LogEntry entry = logRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Log not found with ID: " + id));

        // 2) Delete related incidents first (to avoid orphan references)
        List<Incident> incidents = incidentRepository.findByLogEntry(entry);
        if (!incidents.isEmpty()) {
            incidentRepository.deleteAll(incidents);
        }

        // 3) Finally delete the log entry itself
        logRepository.delete(entry);

        System.out.println("Deleted LogEntry #" + id + " and its related incidents.");
    }
}
