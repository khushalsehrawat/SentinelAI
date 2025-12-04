package com.ai.ThreatDetection.controller;


import com.ai.ThreatDetection.entity.LogEntry;
import com.ai.ThreatDetection.service.AIService;
import com.ai.ThreatDetection.service.LogService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * Logs API:
 * - POST /api/logs (Admin or Analyst)
 * - GET  /api/logs  (Admin or Analyst)
 * - GET  /api/logs/{id}
 *
 * POST triggers AI, Incident creation, and potentially Alerts.
 */
@RestController
@RequestMapping("/api/logs")
public class LogController {


    private static class NewLogPayLoad {
        public String logData;
        public String source;
        public String title;      // short human-readable title
        public String category;   // user-entered category
    }
    private  final LogService logService;
    private  final AIService aiService;

    public LogController(LogService logService, AIService aiService) {
        this.logService = logService;
        this.aiService = aiService;
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    @PostMapping
    public ResponseEntity<LogEntry> ingest(@RequestBody NewLogPayLoad payLoad){
        LogEntry saved = logService.saveAndAnalyze(payLoad.logData, payLoad.source, payLoad.title, payLoad.category);
        return ResponseEntity.ok(saved);
    }



    // ────────────────────────────────
    // GET all logs
    // ────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping
    public List<LogEntry> list() {
        return logService.list();
    }


    // ────────────────────────────────
    // UPLOAD FILE → /api/logs/upload
    // ────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @PostMapping("/upload")
    public ResponseEntity<LogEntry> upload(
            @RequestParam("file") MultipartFile file,
            @RequestParam("source") String source
    ) throws Exception {

        String text = new String(file.getBytes());

        LogEntry saved = logService.saveAndAnalyze(text, source, "Uploaded Log", "GENERAL");
        return ResponseEntity.ok(saved);
    }

    // ────────────────────────────────
    // GET single log
    // ────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping("/{id}")
    public ResponseEntity<LogEntry> get(@PathVariable Long id) {
        return ResponseEntity.ok(logService.find(id));
    }



    // ────────────────────────────────
    // DELETE a log
    // ────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> delete(@PathVariable Long id) {
        logService.delete(id);
        return ResponseEntity.ok("Deleted");
    }

    // ────────────────────────────────
    // AI Explanation Endpoint
    // GET /api/logs/explain/{id}
    // ────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping("/explain/{id}")
    public ResponseEntity<String> explain(@PathVariable Long id) {

        LogEntry log = logService.find(id);

        // if your entity field is logData → use getLogData()
        String aiResponse = aiService.explainLog(log.getLogData());

        return ResponseEntity.ok(aiResponse);
    }


    // ────────────────────────────────
// AI Chat Endpoint  (needed for side panel)
// POST /api/ai/chat
// ────────────────────────────────
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @PostMapping("/chat")
    public ResponseEntity<String> chat(@RequestBody Map<String, String> body) {

        Long logId = Long.parseLong(body.get("logId"));
        String question = body.get("question");

        LogEntry log = logService.find(logId);

        String prompt =
                "Original Error Log:\n" + log.getLogData() +
                        "\n\nUser Question:\n" + question +
                        "\n\nRespond with simple explanation + fix steps.";

        String aiResponse = aiService.chatAboutLog(log.getLogData(), question);

        return ResponseEntity.ok(aiResponse);
    }



}
