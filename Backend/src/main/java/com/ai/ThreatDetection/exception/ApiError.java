package com.ai.ThreatDetection.exception;

import java.time.LocalDateTime;

public class ApiError {

    private String message;
    private LocalDateTime timestamp;
    private String path;

    public ApiError(String message, String path) {
        this.message = message;
        this.timestamp = LocalDateTime.now();
        this.path = path;
    }

    public String getMessage() {
        return message;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getPath() {
        return path;
    }

}
