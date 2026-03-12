# quick_crud.py
# Minimal CRUD test usando Flask + SQLAlchemy (MySQL via pymysql).
# Requiere python3 y las dependencias: Flask, SQLAlchemy, pymysql, python-dotenv

import os
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv
import time

load_dotenv()  # lee .env si existe

DB_USER = os.getenv("DATABASE_USER", "root")
DB_PASS = os.getenv("DATABASE_PASSWORD", "1234")
DB_HOST = os.getenv("DATABASE_HOST", "127.0.0.1")
DB_PORT = os.getenv("DATABASE_PORT", "3306")
DB_NAME = os.getenv("DATABASE_NAME", "idsdb")

DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"

# Engine y sesión
engine = create_engine(DATABASE_URI, pool_pre_ping=True)
Session = sessionmaker(bind=engine)
Base = declarative_base()

# Modelo mínimo
class Event(Base):
    __tablename__ = "events_quick"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), nullable=False)
    protocol = Column(String(20))
    created_at = Column(DateTime, server_default=func.now())

# Función que intenta crear tablas (espera si la DB no está lista)
def ensure_tables(retries=8, delay=3):
    for attempt in range(1, retries+1):
        try:
            Base.metadata.create_all(engine)
            print("Tablas verificadas/creadas correctamente.")
            return
        except Exception as e:
            print(f"[attempt {attempt}] Error creando tablas: {e}")
            if attempt < retries:
                print(f"  esperando {delay} s y reintentando...")
                time.sleep(delay)
            else:
                print("No se pudo crear las tablas tras varios intentos. Abortando.")
                raise

# App Flask
app = Flask(__name__)

@app.route("/events", methods=["POST"])
def create_event():
    data = request.get_json() or {}
    if "source_ip" not in data:
        return jsonify({"error":"source_ip required"}), 400
    sess = Session()
    ev = Event(source_ip=data["source_ip"], protocol=data.get("protocol"))
    sess.add(ev)
    sess.commit()
    ev_id = ev.id
    sess.close()
    return jsonify({"id": ev_id}), 201

@app.route("/events", methods=["GET"])
def list_events():
    sess = Session()
    rows = sess.query(Event).order_by(Event.id.desc()).limit(50).all()
    out = [{"id": r.id, "source_ip": r.source_ip, "protocol": r.protocol, "created_at": r.created_at.isoformat()} for r in rows]
    sess.close()
    return jsonify(out)

if __name__ == "__main__":
    # Intentar crear tablas antes de arrancar la app (con reintentos si DB todavía arranca)
    ensure_tables(retries=8, delay=3)
    app.run(host="0.0.0.0", port=8000, debug=True)
