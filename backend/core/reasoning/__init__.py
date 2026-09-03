"""Autonomous Reasoning Layer (Agentic Redesign).

This package adds a reasoning capability on top of the existing EDR engines:
Perception (event normalization), Working Memory (time-windowed cache),
Tool Executor (engine wrappers), Reasoning Engine (verdict pipelines),
Planning Engine (HTN task graphs) and Long-Term Memory (DB persistence).

All components are inert unless ``config.AGENTIC_MODE`` is enabled, so the
system degrades gracefully to the legacy behavior with zero functionality loss.
"""
