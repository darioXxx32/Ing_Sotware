# src/routes/events.py
from flask import Blueprint, request, jsonify, current_app
from src.db import SessionLocal
from src.models import Event
from sqlalchemy import desc

bp = Blueprint("events", __name__)

@bp.route("/events", methods=["POST"])
def create_event():
    data = request.get_json() or {}
    if "source_ip" not in data:
        return jsonify({"error":"missing source_ip"}), 400
    session = SessionLocal()
    ev = Event(
        source_ip = data.get("source_ip"),
        dest_ip = data.get("dest_ip"),
        source_port = data.get("source_port"),
        dest_port = data.get("dest_port"),
        protocol = data.get("protocol"),
        size = data.get("size"),
        features = data.get("features"),
        label = data.get("label"),
        score = data.get("score"),
        model_version = data.get("model_version")
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    session.close()
    return jsonify({"id": ev.id}), 201

@bp.route("/events", methods=["GET"])
def list_events():
    args = request.args
    page = int(args.get("page", 1))
    size = int(args.get("size", 50))
    q = SessionLocal().query(Event)
    if args.get("source_ip"):
        q = q.filter(Event.source_ip == args.get("source_ip"))
    if args.get("label"):
        q = q.filter(Event.label == args.get("label"))
    total = q.count()
    items = q.order_by(desc(Event.timestamp)).limit(size).offset((page-1)*size).all()
    res = []
    for e in items:
        res.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "protocol": e.protocol,
            "label": e.label,
            "score": e.score,
            "acknowledged": e.acknowledged
        })
    return jsonify({"total": total, "items": res})

@bp.route("/events/<int:event_id>", methods=["GET"])
def get_event(event_id):
    session = SessionLocal()
    e = session.query(Event).get(event_id)
    session.close()
    if not e:
        return jsonify({"error":"not found"}), 404
    return jsonify({
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "source_ip": e.source_ip,
        "dest_ip": e.dest_ip,
        "protocol": e.protocol,
        "features": e.features,
        "label": e.label,
        "score": e.score,
        "acknowledged": e.acknowledged
    })

@bp.route("/events/<int:event_id>/ack", methods=["POST"])
def ack_event(event_id):
    data = request.get_json() or {}
    session = SessionLocal()
    e = session.query(Event).get(event_id)
    if not e:
        session.close()
        return jsonify({"error":"not found"}), 404
    e.acknowledged = True
    e.operator_id = data.get("operator_id")
    session.commit()
    session.close()
    return jsonify({"ok": True})