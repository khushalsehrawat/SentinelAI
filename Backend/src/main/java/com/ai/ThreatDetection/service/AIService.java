package com.ai.ThreatDetection.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.google.cloud.vertexai.VertexAI;
import com.google.cloud.vertexai.api.GenerationConfig;
import com.google.cloud.vertexai.api.GenerateContentResponse;
import com.google.cloud.vertexai.api.Candidate;
import com.google.cloud.vertexai.api.Part;
import com.google.cloud.vertexai.generativeai.GenerativeModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class AIService {

    private final ObjectMapper mapper = new ObjectMapper();

    private static final Set<String> VALID_SEVERITY =
            Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    private static final Set<String> VALID_ACTIONS =
            Set.of("NONE", "BLOCK_IP", "ISOLATE_HOST");

    private static final int MAX_ATTEMPTS = 3;

    private final GenerativeModel model;


    public AIService(
            @Value("${spring.ai.vertex.ai.gemini.project-id}") String projectId,
            @Value("${spring.ai.vertex.ai.gemini.location}") String location
    ) {

        System.setProperty(
                "GOOGLE_APPLICATION_CREDENTIALS",
                "D:/ThreatDetection/Backend/src/main/resources/gcp/credentials.json"
        );


        VertexAI vertexAI = new VertexAI(projectId, location);

        GenerationConfig config = GenerationConfig.newBuilder()
                .setTemperature(0.2f)
                .setMaxOutputTokens(512)
                .build();

        this.model = new GenerativeModel("gemini-1.5-flash", vertexAI)
                .withGenerationConfig(config);
    }

    public Map<String, String> analyzeLog(String logData) {

        for (int i = 1; i <= MAX_ATTEMPTS; i++) {
            try {
                String json = callGemini(logData);
                Map<String, String> parsed = parseJson(json);
                return validateAndCorrect(parsed);

            } catch (Exception e) {
                System.err.println("[AIService] Attempt " + i + " failed: " + e.getMessage());
            }
        }

        return fallback("AI failed after retries.");
    }

    private String callGemini(String log) throws Exception {

        String systemPrompt =
                "You are an enterprise SOC threat analyzer. "
                        + "Return ONLY valid JSON in this EXACT format: "
                        + "{"
                        + "\"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\","
                        + "\"category\": \"string\","
                        + "\"recommendation\": \"string\","
                        + "\"mitre_technique\": \"string or N/A\","
                        + "\"summary\": \"string\","
                        + "\"threat_score\": \"0-100\","
                        + "\"auto_action\": \"NONE|BLOCK_IP|ISOLATE_HOST\""
                        + "}"
                        + "NO markdown, NO extra text.";

        String fullPrompt = systemPrompt + "\nAnalyze:\n" + log;

        GenerateContentResponse response = model.generateContent(fullPrompt);

        StringBuilder sb = new StringBuilder();

        for (Candidate candidate : response.getCandidatesList()) {
            if (candidate.hasContent()) {
                for (Part part : candidate.getContent().getPartsList()) {
                    if (part.hasText()) {
                        sb.append(part.getText());
                    }
                }
            }
        }

        return sanitize(sb.toString());
    }

    private String sanitize(String text) {
        if (text == null) return "";

        text = text.replace("```json", "")
                .replace("```", "")
                .replace("'", "\"")
                .trim();

        if (text.contains("{") && text.contains("}")) {
            text = text.substring(text.indexOf("{"), text.lastIndexOf("}") + 1);
        }

        return text.trim();
    }

    private Map<String, String> parseJson(String raw) throws Exception {

        JsonNode node = mapper.readTree(raw);

        Map<String, String> map = new HashMap<>();
        map.put("severity", node.path("severity").asText(""));
        map.put("category", node.path("category").asText(""));
        map.put("recommendation", node.path("recommendation").asText(""));
        map.put("mitre_technique", node.path("mitre_technique").asText(""));
        map.put("summary", node.path("summary").asText(""));
        map.put("threat_score", node.path("threat_score").asText(""));
        map.put("auto_action", node.path("auto_action").asText(""));

        return map;
    }

    private Map<String, String> validateAndCorrect(Map<String, String> in) {

        Map<String, String> out = new HashMap<>();

        String sev = in.getOrDefault("severity", "LOW").toUpperCase();
        if (!VALID_SEVERITY.contains(sev)) sev = "LOW";
        out.put("severity", sev);

        String cat = in.getOrDefault("category", "General");
        out.put("category", cat);

        String rec = in.getOrDefault("recommendation", "No recommendation.");
        out.put("recommendation", rec);

        String mitre = in.getOrDefault("mitre_technique", "N/A");
        out.put("mitre_technique", mitre);

        String summary = in.getOrDefault("summary", "");
        if (summary.isEmpty()) summary = "Event severity " + sev + " in category " + cat;
        out.put("summary", summary);

        int score;
        try {
            score = Integer.parseInt(in.get("threat_score"));
        } catch (Exception e) {
            score = switch (sev) {
                case "CRITICAL" -> 90;
                case "HIGH" -> 75;
                case "MEDIUM" -> 50;
                default -> 20;
            };
        }

        if (score < 0) score = 0;
        if (score > 100) score = 100;

        out.put("threat_score", String.valueOf(score));

        String auto = in.getOrDefault("auto_action", "NONE").toUpperCase();
        if (!VALID_ACTIONS.contains(auto))
            auto = (score >= 80) ? "BLOCK_IP" : "NONE";

        out.put("auto_action", auto);

        return out;
    }

    private Map<String, String> fallback(String reason) {

        Map<String, String> m = new HashMap<>();
        m.put("severity", "LOW");
        m.put("category", "General");
        m.put("recommendation", "Fallback: " + reason);
        m.put("mitre_technique", "N/A");
        m.put("summary", "AI unavailable.");
        m.put("threat_score", "10");
        m.put("auto_action", "NONE");

        return m;
    }

    public String explainLog(String text) {
        Map<String, String> result = analyzeLog(text);

        String explanation =
                "Severity: " + result.get("severity") + "\n" +
                        "Category: " + result.get("category") + "\n" +
                        "Threat Score: " + result.get("threat_score") + "\n" +
                        "MITRE Technique: " + result.get("mitre_technique") + "\n" +
                        "\nSummary:\n" + result.get("summary") + "\n" +
                        "\nRecommendation:\n" + result.get("recommendation");

        return explanation;
    }


    public String chatAboutLog(String logData, String question) {

        String prompt =
                "You are a senior software engineer.\n" +
                        "Explain the issue in the following log in very simple language.\n" +
                        "Then answer the user's question step-by-step.\n\n" +
                        "=== LOG ===\n" + logData + "\n\n" +
                        "=== USER QUESTION ===\n" + question + "\n\n" +
                        "Give a direct human-like helpful answer. Do NOT return JSON.";

        try {
            GenerateContentResponse response = model.generateContent(prompt);

            StringBuilder sb = new StringBuilder();
            for (Candidate c : response.getCandidatesList()) {
                if (c.hasContent()) {
                    for (Part p : c.getContent().getPartsList()) {
                        if (p.hasText()) {
                            sb.append(p.getText());
                        }
                    }
                }
            }
            return sb.toString().trim();
        } catch (Exception e) {
            return "AI Chat failed: " + e.getMessage();
        }
    }


}
