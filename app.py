from pathlib import Path

from flask import Flask, jsonify, send_from_directory

from backend.config import Config
from backend.extensions import db


BASE_DIR = Path(__file__).resolve().parent


def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    db.init_app(app)

    from backend.models import User, Scan
    from backend.routes import auth_bp

    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()

    # Allow Google OAuth popup postMessage handshakes and prevent 404 favicon logs
    @app.after_request
    def add_security_headers(response):
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
        return response

    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    # Homepage
    @app.route("/")
    def home():
        return send_from_directory(BASE_DIR, "index.html")

    # Other frontend HTML pages
    @app.route("/<page>")
    def frontend_pages(page):
        allowed_pages = {
            "login.html",
            "register.html",
            "dashboard.html",
            "profile.html",
            "url_scanner.html",
            "email_analyzer.html",
            "reports.html",
            "training.html",
            "pricing.html"
        }

        if page not in allowed_pages:
            return jsonify({
                "status": "error",
                "message": "Page not found"
            }), 404

        return send_from_directory(BASE_DIR, page)

    # CSS files
    @app.route("/css/<path:filename>")
    def css_files(filename):
        return send_from_directory(BASE_DIR / "css", filename)

    # JavaScript files
    @app.route("/js/<path:filename>")
    def js_files(filename):
        return send_from_directory(BASE_DIR / "js", filename)

    # Image files
    @app.route("/images/<path:filename>")
    def image_files(filename):
        return send_from_directory(BASE_DIR / "images", filename)

    # Backend health check
    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "success",
            "message": "SecureNet backend is running"
        })

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False,
        threaded=True
    )