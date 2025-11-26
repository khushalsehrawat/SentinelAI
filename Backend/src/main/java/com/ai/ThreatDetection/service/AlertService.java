package com.ai.ThreatDetection.service;


import com.ai.ThreatDetection.dto.AlertResponse;
import com.ai.ThreatDetection.entity.Alert;
import com.ai.ThreatDetection.entity.Incident;
import com.ai.ThreatDetection.repository.AlertRepository;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * AlertService
 * - creates Alert rows
 * - sends email (and can be extended for SMS)
 * - returns clean DTOs to controllers
 */
@Service
public class AlertService {

    private final AlertRepository alertRepository;
    private final JavaMailSender mailSender;


    public AlertService(AlertRepository alertRepository, JavaMailSender mailSender) {
        this.alertRepository = alertRepository;
        this.mailSender = mailSender;
    }

    public Alert createEmailAlert(Incident incident, String severity, String message, String toEmail)
    {
        Alert alert = new Alert("EMAIL", message, incident, severity);
        Alert saved = alertRepository.save(alert);

        // send email (best-effort; if mail fails we still keep alert row)
        try {
            SimpleMailMessage mail = new SimpleMailMessage();
            mail.setTo(toEmail);
            mail.setSubject("[Threat Alert] Severity: " + severity);
            mail.setText(message);
            mailSender.send(mail);
            saved.setStatus("SENT");
            saved = alertRepository.save(saved);
        } catch (Exception e) {
            // stays PENDING; can be retried later
        }
        return saved;
    }

    public List<AlertResponse> list(){
        return alertRepository.findAll().stream()
                .map(a ->
                        new AlertResponse(
                                a.getId(), a.getType(),a.getStatus(), a.getSeverity(),
                                a.getMessage(),
                                a.getIncident() != null ? a.getIncident().getId() : null,
                                a.getCreatedAt(),
                                a.getTitle(),
                                a.getUserCategory()
                        )
                        ).collect(Collectors.toList());
    }

}
