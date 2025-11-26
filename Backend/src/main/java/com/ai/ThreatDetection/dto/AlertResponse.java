package com.ai.ThreatDetection.dto;

import java.util.Date;

public class AlertResponse {

    private Long id;
    private String type;
    private String status;
    private String severity;    // LOW/MEDIUM/HIGH/CRITICAL
    private String message;
    private Long incidentId;
    private Date createdAt;
    private String title;
    private String userCategory;


    public AlertResponse(Long id, String type, String status, String severity, String message, Long incidentId, Date createdAt, String title, String userCategory) {
        this.id = id;
        this.type = type;
        this.status = status;
        this.severity = severity;
        this.message = message;
        this.incidentId = incidentId;
        this.createdAt = createdAt;
        this.title = title;
        this.userCategory = userCategory;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Long getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(Long incidentId) {
        this.incidentId = incidentId;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUserCategory() {
        return userCategory;
    }

    public void setUserCategory(String userCategory) {
        this.userCategory = userCategory;
    }
}
