import pytest
from app import create_app, db as _db
from app.models import User

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", # In-memory DB for fast testing
        "WTF_CSRF_ENABLED": False # Disable CSRF tokens for easier test form submissions
    })

    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_client(client, app):
    """Helper fixture that registers and logs in a test user automatically."""
    with app.app_context():
        user = User(username="testanalyst", email="analyst@cyberpath.test")
        user.set_password("SecurePassword123!")
        _db.session.add(user)
        _db.session.commit()
    
    client.post("/login", data={
        "username": "testanalyst",
        "password": "SecurePassword123!"
    }, follow_redirects=True)
    
    return client