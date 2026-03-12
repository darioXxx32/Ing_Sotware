# src/models.py
from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Float, Boolean, JSON
from sqlalchemy.sql import func
from src.db import Base

class Event(Base):
    __tablename__ = "events"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now(), index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    size = Column(Integer, nullable=True)
    features = Column(JSON, nullable=True)   # requiere MySQL >=5.7
    label = Column(String(50), nullable=True, index=True)
    score = Column(Float, nullable=True)
    model_version = Column(String(50), nullable=True)
    acknowledged = Column(Boolean, default=False)
    operator_id = Column(Integer, nullable=True)