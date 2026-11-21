# SentinelAI - AI Threat Detection & SOC Workbench

SentinelAI is an end-to-end SOC simulator that ingests raw logs, enriches them with Vertex AI (Gemini), builds incidents, fires alerts, and gives analysts an AI sidekick to explain and remediate issues. It ships with a Spring Boot backend, JWT-based RBAC, MySQL persistence, email notifications, and a cyber-style frontend dashboard.

```
Client UI / API -> LogService -> AIService (Gemini)
                 -> LogEntry (DB)
                 -> Incident (DB)
                 -> AlertService -> Email + Alerts UI
                 -> AI chat for explanations/fix steps
```

## What you get (quick view)
- Log ingestion via API, paste, or file upload (logs.html) with AI severity/category/recommendations.
- Automatic incident creation with MITRE mapping, threat scores, and PDF export (incident-details.html).
- Alerting pipeline: HIGH/CRITICAL incidents trigger alert rows and email sends; status can be marked seen/resolved (alerts.html).
- AI assistant: explain any log and chat about fixes inline in the logs screen.
- RBAC: ADMIN vs ANALYST enforced by Spring Security + JWT; admin-only user management (admin-users.html).
- Dashboards: KPIs and charts (dashboard.html); marketing/overview landing page (index.html).

## Architecture and stack
- Backend: Java 21, Spring Boot 3.5, Spring Data JPA (MySQL), Spring Security + JWT, JavaMailSender, Vertex AI client for Gemini 1.5 Flash.
- Frontend: HTML/CSS/JS, Bootstrap 5, FontAwesome, Chart.js, AOS/GSAP animations. Static files hitting the REST API at http://localhost:8080/api.
- Data flow: LogService saves the raw log -> AIService enriches (severity, category, MITRE, score, auto_action) -> Incident is created -> AlertService emails and records alerts for HIGH/CRITICAL -> UIs read everything via /api/**.
- CORS: CorsConfig allows http://localhost and http://127.0.0.1 on ports 3000, 5500, 8081 for dev.

### Repo layout
- Backend/ Spring Boot app (controllers, services, security, entities, repositories, AI + mail wiring).
- Frontend/ Static pages for landing, login/register, dashboard, logs, incidents, alerts, admin users, IP lookup (WIP).
- Backend/src/main/resources/gcp/credentials.json Vertex AI credentials (path is hard-coded in AIService).
- Overview.docx High-level description (optional reading).

## Data model (what is stored)
| Entity | Purpose | Key fields | Relationships |
| --- | --- | --- | --- |
| User | Auth principal with roles | email, password (BCrypt), role (ADMIN, ANALYST), createdAt | none |
| LogEntry | Raw log plus AI tags | logData, source, title, userCategory, severity, category, recommendation, timestamp | OneToOne -> Incident |
| Incident | AI-generated incident record | status (OPEN/RESOLVED), severity, details (summary, MITRE, score, recommendation), detectedAt | OneToOne -> LogEntry |
| Alert | Notification record | type (EMAIL), status (PENDING/SENT/SEEN/RESOLVED), severity, message, title, userCategory, createdAt | ManyToOne -> Incident |
| Organization | Placeholder for multi-tenant expansion | name | none (not yet used) |

## API surface (roles in brackets)
Base URL: http://localhost:8080/api

Auth (public)
- POST /auth/register register user {email, password, role}.
- POST /auth/login -> { token, email, roles } (JWT goes in Authorization: Bearer <token>).

Logs (ADMIN or ANALYST)
- GET /logs list all logs.
- POST /logs ingest body {logData, source, title, category} -> triggers AI, incident, possible alert.
- POST /logs/upload form-data file, source -> ingest file contents.
- GET /logs/{id} get one log.
- DELETE /logs/{id} remove log and related incidents.
- GET /logs/explain/{id} AI summary of a log.
- POST /logs/chat {logId, question} AI side-chat about that log.

Incidents (ADMIN or ANALYST)
- GET /incidents list.
- GET /incidents/{id} details (includes linked LogEntry text).
- PUT /incidents/{id}/status?value=RESOLVED update status.

Alerts
- GET /alerts (ADMIN or ANALYST) list alerts.
- PUT /alerts/{id}/status (ADMIN) body {status} mark SEEN/RESOLVED.

Users
- GET /users (ADMIN) list users.
- DELETE /admin/users/{id} (ADMIN) remove user.
- PUT /admin/users/{id}/reset-password (ADMIN) {newPassword}.
- PUT /admin/users/{id}/role (ADMIN) {role} change role.

### Sample calls
```bash
# Register first admin
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"ChangeMe123","role":"ADMIN"}'

# Login to get JWT
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"ChangeMe123"}'
# -> use .token from response below

# Ingest a log (needs Bearer token)
curl -X POST http://localhost:8080/api/logs \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{"logData":"Unauthorized SSH login attempt from 10.0.0.5","source":"ssh-gateway","title":"SSH brute force","category":"Access"}'
```

## How the AI pipeline works
- AIService.analyzeLog sends the log text to Gemini 1.5 Flash via the Vertex AI SDK.
- Expected JSON back: severity, category, recommendation, mitre_technique, summary, threat_score (0-100), auto_action (NONE|BLOCK_IP|ISOLATE_HOST).
- Results are sanitized, validated, and defaulted if Gemini misbehaves; severity/score are clamped and auto_action is corrected.
- LogService.saveAndAnalyze orchestrates:
  1) Save base LogEntry.
  2) Call AI -> update LogEntry with severity/category/recommendation.
  3) Create Incident with summary, MITRE, and threat score.
  4) If severity HIGH/CRITICAL: create Alert and send email via JavaMailSender.
  5) Log auto-action suggestions (no real firewall calls yet; hook is in place).
- /logs/explain/{id} formats an analyst-friendly summary; /logs/chat lets you ask follow-up questions.

## Frontend walkthrough (what each page does)
- index.html landing: explains the pipeline and links to modules.
- login.html / register.html: JWT auth; role selection during registration.
- dashboard.html: KPIs (total incidents/logs, critical count, average threat score) and charts (severity pie, MITRE bar, timeline, heatmap).
- logs.html: view/search/export logs; ingest via paste/upload; inject sample logs; AI explain modal; AI side-chat; delete logs.
- incidents.html: incident table with severity badges, MITRE and score parsing, CSV/JSON export.
- incident-details.html: detailed view with raw log, MITRE, recommendation, threat gauge, PDF export.
- alerts.html: alert table with filters; admin can mark seen/resolved; click-through to incident details.
- admin-users.html: list users, create (via register UI), reset password, change role, delete (admin only).
- ip-lookup.html: placeholder for enrichment expansion (UI only, not wired).
- sample-logs.json: sample data used for quick injections.

## Setup and run (local)
Prereqs: Java 21, Maven, MySQL running locally, and a simple static server (Live Server, python -m http.server, or npx serve).

1) Database: create a schema named threat (or update the URL).
   ```sql
   CREATE DATABASE threat CHARACTER SET utf8mb4;
   ```
2) Configure secrets (replace hard-coded values in Backend/src/main/resources/application.properties with your own; best is env vars):
   ```
   spring.datasource.url=jdbc:mysql://localhost:3306/threat
   spring.datasource.username=<db_user>
   spring.datasource.password=<db_pass>
   jwt.secret=<at_least_32_chars_secret>
   jwt.expiration=86400000
   spring.mail.host=smtp.gmail.com
   spring.mail.port=587
   spring.mail.username=<smtp_user>
   spring.mail.password=<smtp_app_password>
   spring.ai.vertex.ai.gemini.api-key=<vertex_api_key>
   spring.ai.vertex.ai.gemini.project-id=<gcp_project>
   spring.ai.vertex.ai.gemini.location=us-central1
   spring.ai.vertex.ai.gemini.model=gemini-1.5-flash
   ```
   Place your Vertex service account JSON at Backend/src/main/resources/gcp/credentials.json or update the path in AIService (GOOGLE_APPLICATION_CREDENTIALS).

3) Run backend:
   ```bash
   cd Backend
   mvn spring-boot:run
   ```
   The API listens on http://localhost:8080/api.

4) Run frontend:
   ```bash
   cd Frontend
   npx serve .   # or python -m http.server 5500, or use VS Code Live Server
   ```
   Open http://localhost:5500/index.html (adjust to your chosen port). The UI expects the backend at http://localhost:8080.

5) First-run checklist:
   - Register an ADMIN via register.html.
   - Login, copy the JWT (auto-stored in localStorage).
   - Go to Logs, click "Inject sample logs" to see AI-driven incidents/alerts.
   - Explore Incident details, export a PDF, then check Alerts and Dashboard.

## Security and RBAC
- Roles: ADMIN and ANALYST. ADMIN can manage users, alerts status, delete logs/incidents; both roles can view/ingest logs and view incidents/alerts.
- Authentication: JWT via Authorization: Bearer <token>; tokens embed roles claim; JwtAuthFilter validates and sets the SecurityContext.
- Password storage: BCrypt encoder.
- CORS: localhost dev origins only; adjust CorsConfig for other hosts.
- Secrets: Replace the committed sample secrets with your own; prefer environment variables or an external config.

## Demo script (talk track)
1) Brief the pipeline (diagram above).
2) Show login and dashboard KPIs/charts.
3) Go to Logs: paste a log, run AI explanation, open AI chat, and watch incident/alert creation.
4) Open Incidents, drill into details, export PDF.
5) Open Alerts, mark SEEN/RESOLVED.
6) Show Admin Users (role change/reset password).

## Troubleshooting
- If AI calls fail, AIService falls back to safe defaults; check Vertex credentials and API key.
- If emails are not sent, verify SMTP creds; alerts still persist even if mail send fails.
- CORS errors: make sure you are serving the frontend from an allowed origin/port.
- DB errors: confirm the MySQL URL/user/password and that the threat schema exists; schema auto-updates via spring.jpa.hibernate.ddl-auto=update.

---
Built for showcasing GenAI + Spring Security + SOC workflows in one compact project.

## Website metadata

Both static UI locations, `Frontend/` and `Backend/src/main/resources/static/`, include page-specific descriptions, viewport metadata, TheBenzzCreations author/creator metadata, Open Graph metadata and Twitter card metadata. All 21 HTML files retain their original titles and SentinelAI branding.

Each deployment's homepage (`index.html`) includes one WebSite JSON-LD block identifying the genuine creator and one visible developer credit in the existing footer. These are two deployment copies, not duplicate credits on a served page. The promotional link uses `rel="noopener noreferrer nofollow"`.

The official public URL has not been supplied. Canonical links, `og:url` and the WebSite `url` are omitted until SentinelAI's public URL is verified. Do not use the developer website as the application's canonical URL. No dedicated social preview image is configured. Structured data does not guarantee search rich results.

The UI consists of static HTML with embedded CSS/JavaScript, not Thymeleaf templates. There is no frontend package manifest or build command. Backend compilation targets Java 21; application tests also require the backend's configured services.

## Development

Developed by [TheBenzzCreations](https://www.thebenzzcreations.com/).

TheBenzzCreations builds custom websites, mobile applications, business software, e-commerce platforms and AI automation solutions.

For development enquiries, visit our official website.
