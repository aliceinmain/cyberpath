from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

from app import db
from app.forms import (AccountSettingsForm, IncidentForm, IncidentUpdateForm,
                       LoginForm, NoteForm, RegistrationForm)
from app.models import Incident, InvestigationNote, LogEntry, User
from app.utils import (MAX_LOG_UPLOAD_BYTES, allowed_log_filename,
                       investigate_ip, parse_log_text)

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data.strip(), email=form.email.data.strip().lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Your account has been created. You can now log in.", "success")
        return redirect(url_for("main.login"))
    return render_template("register.html", form=form)


@main.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter(func.lower(User.email) == email).first()
        if user is not None and user.check_password(form.password.data):
            session.clear()
            login_user(user)
            flash("You are now logged in.", "success")
            return redirect(url_for("main.dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html", form=form)


@main.route("/settings", methods=["GET", "POST"])
@login_required
def account_settings():
    form = AccountSettingsForm()
    form.user_id = current_user.id
    if request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email

    if form.validate_on_submit():
        current_user.username = form.username.data.strip()
        current_user.email = form.email.data.strip().lower()

        if form.new_password.data:
            if not check_password_hash(current_user.password_hash, form.current_password.data):
                form.current_password.errors.append("That current password is incorrect.")
                flash("Your account details were not changed. Check the password field and try again.", "error")
                return render_template("settings.html", form=form)
            current_user.set_password(form.new_password.data)

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            form.username.errors.append("That username or email address is already in use.")
            flash("We couldn't save those details. Please choose a different username and email address.", "error")
            return render_template("settings.html", form=form)

        flash("Your account settings have been updated.", "success")
        return redirect(url_for("main.account_settings"))

    return render_template("settings.html", form=form)


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))


@main.route("/dashboard")
@login_required
def dashboard():
    owned = Incident.query.filter_by(user_id=current_user.id)
    total_count = owned.count()
    open_count = owned.filter(Incident.status == "Open").count()
    priority_count = owned.filter(Incident.severity.in_(["High", "Critical"])).count()

    query = owned
    keyword = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    severity = request.args.get("severity", "").strip()
    if keyword:
        pattern = f"%{keyword}%"
        query = query.filter(or_(Incident.title.ilike(pattern), Incident.description.ilike(pattern)))
    if status in {"Open", "Investigating", "Closed"}:
        query = query.filter(Incident.status == status)
    else:
        status = ""
    if severity in {"Low", "Medium", "High", "Critical"}:
        query = query.filter(Incident.severity == severity)
    else:
        severity = ""

    incidents = query.order_by(Incident.created_at.desc()).all()
    return render_template("dashboard.html", incidents=incidents, total_count=total_count,
                           open_count=open_count, priority_count=priority_count,
                           q=keyword, status=status, severity=severity)


@main.route("/incidents/new", methods=["GET", "POST"])
@login_required
def create_incident():
    form = IncidentForm()
    if form.validate_on_submit():
        incident = Incident(title=form.title.data.strip(), description=form.description.data.strip(),
                            severity=form.severity.data, status=form.status.data,
                            user_id=current_user.id)
        db.session.add(incident)
        db.session.commit()
        flash("Incident created successfully.", "success")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))
    return render_template("create_incident.html", form=form)


def get_owned_incident(incident_id):
    incident = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first()
    if incident is None:
        abort(404)
    return incident


@main.route("/incidents/<int:incident_id>", methods=["GET", "POST"])
@login_required
def incident_detail(incident_id):
    incident = get_owned_incident(incident_id)
    form = IncidentUpdateForm()
    if request.method == "GET":
        form.status.data = incident.status
        form.severity.data = incident.severity
    elif form.validate_on_submit():
        incident.status = form.status.data
        incident.severity = form.severity.data
        db.session.commit()
        flash("Incident updated successfully.", "success")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))
    log_entries = LogEntry.query.join(Incident).filter(
        Incident.id == incident.id, Incident.user_id == current_user.id
    ).order_by(LogEntry.timestamp.asc(), LogEntry.id.asc()).all()
    ip_addresses = sorted({entry.source_ip for entry in log_entries} |
                          {entry.destination_ip for entry in log_entries
                           if entry.destination_ip != "Unknown"})
    notes = InvestigationNote.query.join(Incident).filter(
        Incident.id == incident.id, Incident.user_id == current_user.id
    ).order_by(InvestigationNote.created_at.asc(), InvestigationNote.id.asc()).all()
    note_form = NoteForm()
    return render_template("incident_detail.html", incident=incident, form=form,
                           note_form=note_form, notes=notes,
                           log_entries=log_entries, ip_addresses=ip_addresses)


@main.route("/incidents/<int:incident_id>/upload-logs", methods=["POST"])
@login_required
def upload_logs(incident_id):
    incident = get_owned_incident(incident_id)
    uploaded = request.files.get("log_file")
    if uploaded is None or not uploaded.filename:
        flash("Choose a log file to upload.", "error")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))
    if not allowed_log_filename(uploaded.filename):
        flash("Unsupported file type. Upload a .log, .txt, or .csv file.", "error")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))

    content = uploaded.stream.read(MAX_LOG_UPLOAD_BYTES + 1)
    if len(content) > MAX_LOG_UPLOAD_BYTES:
        flash("The log file exceeds the 5 MB upload limit.", "error")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))
    try:
        log_text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("The log file must be valid UTF-8 text.", "error")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))

    entries, skipped = parse_log_text(log_text, incident.id)
    if not entries:
        flash("No valid log events were found. Each line needs a supported timestamp and IP address.", "error")
        return redirect(url_for("main.incident_detail", incident_id=incident.id))

    db.session.add_all(entries)
    db.session.commit()
    message = f"Imported {len(entries)} log event(s)."
    if skipped:
        message += f" Skipped {skipped} line(s) that could not be parsed."
    flash(message, "success")
    return redirect(url_for("main.incident_detail", incident_id=incident.id))


@main.route("/incidents/<int:incident_id>/timeline")
@login_required
def incident_timeline(incident_id):
    incident = get_owned_incident(incident_id)
    log_entries = LogEntry.query.join(Incident).filter(
        Incident.id == incident.id, Incident.user_id == current_user.id
    ).order_by(LogEntry.timestamp.asc(), LogEntry.id.asc()).all()
    return render_template("incident_timeline.html", incident=incident,
                           log_entries=log_entries)


@main.route("/incidents/<int:incident_id>/ip-lookup")
@login_required
def ip_lookup(incident_id):
    incident = get_owned_incident(incident_id)
    ip_address = request.args.get("ip", "").strip()
    # Only search within this user's incident, never across workspaces.
    entries = LogEntry.query.join(Incident).filter(
        Incident.id == incident.id, Incident.user_id == current_user.id
    ).all()
    profile = investigate_ip(entries, ip_address) if ip_address else None
    if ip_address and profile is None:
        flash("Enter a valid IP address.", "error")
    elif profile is not None and profile["request_count"] == 0:
        flash("This IP address does not appear in this incident's logs.", "info")
    return render_template("ip_lookup.html", incident=incident, profile=profile,
                           ip_address=ip_address)


@main.route("/incidents/<int:incident_id>/notes", methods=["POST"])
@login_required
def add_investigation_note(incident_id):
    incident = get_owned_incident(incident_id)
    form = NoteForm()
    if form.validate_on_submit():
        content = (form.content.data or "").strip()
        if not content:
            flash("Note content cannot be empty.", "error")
        else:
            db.session.add(InvestigationNote(content=content, incident_id=incident.id))
            db.session.commit()
            flash("Investigation note saved.", "success")
    else:
        flash("Please enter a valid investigation note.", "error")
    return redirect(url_for("main.incident_detail", incident_id=incident.id))


@main.route("/incidents/<int:incident_id>/report")
@login_required
def incident_report(incident_id):
    incident = get_owned_incident(incident_id)
    log_entries = LogEntry.query.join(Incident).filter(
        Incident.id == incident.id, Incident.user_id == current_user.id
    ).order_by(LogEntry.timestamp.asc(), LogEntry.id.asc()).all()
    notes = InvestigationNote.query.join(Incident).filter(
        Incident.id == incident.id, Incident.user_id == current_user.id
    ).order_by(InvestigationNote.created_at.asc(), InvestigationNote.id.asc()).all()

    ip_addresses = sorted({entry.source_ip for entry in log_entries} |
                          {entry.destination_ip for entry in log_entries
                           if entry.destination_ip != "Unknown"})
    ip_findings = [investigate_ip(log_entries, address) for address in ip_addresses]
    ip_findings = [finding for finding in ip_findings if finding is not None]
    ip_findings.sort(key=lambda finding: (-finding["request_count"], finding["ip"]))

    from datetime import datetime
    return render_template(
        "incident_report.html", incident=incident, log_entries=log_entries,
        notes=notes, ip_findings=ip_findings, generated_at=datetime.utcnow(),
    )


@main.route("/incidents/<int:incident_id>/delete", methods=["POST"])
@login_required
def delete_incident(incident_id):
    incident = get_owned_incident(incident_id)
    db.session.delete(incident)
    db.session.commit()
    flash("Incident deleted successfully.", "success")
    return redirect(url_for("main.dashboard"))
