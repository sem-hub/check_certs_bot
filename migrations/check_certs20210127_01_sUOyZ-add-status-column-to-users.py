"""
Add status column to users
"""

from yoyo import step

__depends__ = {}

steps = [
    step("ALTER TABLE users ADD COLUMN status TEXT")
]
