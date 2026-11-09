import os

BASE_DIR = os.path.abspath(
    os.path.dirname(os.path.dirname(__file__))
)


class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-key-change-later"
    )

    SQLALCHEMY_DATABASE_URI = (
        "sqlite:///" + os.path.join(BASE_DIR, "securenet.db")
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_PATH = "/"
    SESSION_COOKIE_DOMAIN = None

    # Google OAuth Client ID
    GOOGLE_CLIENT_ID = os.environ.get(
        "GOOGLE_CLIENT_ID",
        "719826006412-gls5t8vu33i832btarvdbijrv4qjkfd3.apps.googleusercontent.com"
    )