# ============================================================================
# argus/__main__.py
# -----------------
# Entry point for `python -m argus` execution.
# ============================================================================

"""
Allow running Argus as a module:
    python -m argus --target https://example.com
"""

if __name__ == '__main__':
    import sys
    from .cli import main
    sys.exit(main())