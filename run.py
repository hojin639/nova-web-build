#!/usr/bin/env python3
"""NOVA Web launcher — monkey-patches eventlet before imports."""
import eventlet
eventlet.monkey_patch()

from app import main
main()
