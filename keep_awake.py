"""Keep-awake utility module using wakepy.

Provides context manager to prevent system sleep during long-running scans
while still allowing screen lock and screensaver.
"""
from wakepy import keep

def keep_awake_context():
    """Return wakepy keep.running() context manager.
    
    This mode prevents automatic system sleep while allowing:
    - Screen lock
    - Screensaver activation
    - Manual sleep
    
    Usage:
        with keep_awake_context():
            # Your long-running code here
            run_scan()
    """
    return keep.running()
