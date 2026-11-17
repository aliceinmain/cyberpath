# CyberPath — Project Rules & Specification

## Product Purpose
A web-based platform helping cybersecurity students and junior analysts practice incident investigation using simulated datasets, log analysis, IP investigation, and evidence documentation.

## Tech Stack
- Python 3 + Flask (`app/` factory or blueprint structure)
- SQLite + Flask-SQLAlchemy (`instance/`)
- Flask-Login + Flask-WTF (CSRF protection & form validation)
- Jinja2 HTML templates (`app/templates/`) & static assets (`app/static/`)

## Functional Requirements (Strict Scope)
- FR-01: User registration and login
- FR-02: Personalized dashboard
- FR-03: Create and manage incidents
- FR-04: Search and filter incidents
- FR-05: Upload and parse sample logs
- FR-06: View event timelines
- FR-07: Investigate IP addresses
- FR-08: Save investigation notes
- FR-09: Generate incident reports
- FR-10: Manage account settings

## Security & Scope Guardrails
1. **No Scope Creep:** Only implement features explicitly listed in FR-01 through FR-10. Do not add unrequested features, roles, or third-party APIs.
2. **Password Security:** Hash all passwords with `werkzeug.security.generate_password_hash`. Never store plaintext passwords.
3. **Workspace Isolation:** Every query for incidents, logs, or notes MUST filter by `current_user.id`. Never allow cross-user data access.
4. **Input & File Validation:** Validate all form inputs server-side. Restrict uploaded log files by extension and file size.
5. **Simulated Data Only:** Rely strictly on local simulated datasets.