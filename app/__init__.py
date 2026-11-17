from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_class=None):
    app = Flask(__name__)
    if config_class is None:
        app.config.from_object("config.Config")
    else:
        app.config.from_object(config_class)

    # Hard cap all incoming request bodies; the upload route also enforces
    # the same limit while reading the file stream.
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "main.login"
    login_manager.login_message_category = "info"

    from app.routes import main
    app.register_blueprint(main)

    # Import models before creating tables so SQLAlchemy knows every table.
    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    return app


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
