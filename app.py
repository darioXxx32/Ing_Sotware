# app.py (simplificado)
from flask import Flask
from src.db import engine, Base
from src.routes.events import bp as events_bp

def create_app():
    app = Flask(__name__)
    # registrar blueprints
    app.register_blueprint(events_bp)
    # crear tablas si no existen
    Base.metadata.create_all(bind=engine)
    return app

if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8000, debug=True)