from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

from app import db
from app.models import User


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", message="Passwords must match.")])
    submit = SubmitField("Create account")

    def validate_username(self, field):
        username = field.data.strip()
        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            raise ValidationError("That username is already taken.")

    def validate_email(self, field):
        email = field.data.strip().lower()
        if User.query.filter(db.func.lower(User.email) == email).first():
            raise ValidationError("An account with that email already exists.")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")


class IncidentForm(FlaskForm):
    title = StringField("Incident title", validators=[DataRequired(), Length(max=150)])
    description = TextAreaField("Description", validators=[DataRequired()])
    severity = SelectField("Severity", choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Critical", "Critical")], validators=[DataRequired()])
    status = SelectField("Status", choices=[("Open", "Open"), ("Investigating", "Investigating"), ("Closed", "Closed")], validators=[DataRequired()])
    submit = SubmitField("Create incident")


class IncidentUpdateForm(FlaskForm):
    severity = SelectField("Severity", choices=[("Low", "Low"), ("Medium", "Medium"), ("High", "High"), ("Critical", "Critical")], validators=[DataRequired()])
    status = SelectField("Status", choices=[("Open", "Open"), ("Investigating", "Investigating"), ("Closed", "Closed")], validators=[DataRequired()])
    submit = SubmitField("Save changes")


class NoteForm(FlaskForm):
    content = TextAreaField(
        "Investigation note",
        validators=[DataRequired(), Length(max=10000)],
    )
    submit = SubmitField("Save note")


class AccountSettingsForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    email = EmailField("Email address", validators=[DataRequired(), Email(), Length(max=120)])
    current_password = PasswordField("Current password")
    new_password = PasswordField("New password", validators=[Length(min=8, max=128)])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[EqualTo("new_password", message="The new passwords do not match.")],
    )
    submit = SubmitField("Save account changes")

    def validate_username(self, field):
        username = field.data.strip()
        existing = User.query.filter(
            db.func.lower(User.username) == username.lower(),
            User.id != self.user_id,
        ).first()
        if existing:
            raise ValidationError("That username is already in use.")

    def validate_email(self, field):
        email = field.data.strip().lower()
        existing = User.query.filter(
            db.func.lower(User.email) == email,
            User.id != self.user_id,
        ).first()
        if existing:
            raise ValidationError("That email address is already associated with another account.")

    def validate_current_password(self, field):
        if self.new_password.data and not field.data:
            raise ValidationError("Enter your current password to set a new one.")

    def validate_new_password(self, field):
        if field.data and len(field.data) < 8:
            raise ValidationError("Your new password must contain at least 8 characters.")
