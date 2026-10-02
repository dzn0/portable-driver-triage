"""DrvEye → bundle adapter.

Takes a `.sys` from pipeline_out/drivers/ + a scope profile, drives DrvEye,
reshapes the result into the per-bundle layout defined in AGENTS.md, and
appends a conforming row to reports/index.jsonl.
"""
