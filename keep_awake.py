"""Keep-awake utility module using wakepy.

Provides context manager to prevent system sleep during long-running scans
while still allowing screen lock and screensaver.
"""
import logging
import sys
from contextlib import contextmanager

try:
    from wakepy import keep
    WAKEPY_AVAILABLE = True
except ImportError:
    WAKEPY_AVAILABLE = False
    logging.warning('wakepy module not available - keep-awake functionality disabled')

# Configure logging for this module
logger = logging.getLogger(__name__)

@contextmanager
def keep_awake_context():
    """Context manager to prevent system sleep during execution.
    
    This mode prevents automatic system sleep while allowing:
    - Screen lock
    - Screensaver activation
    - Manual sleep
    
    Features:
    - Proper error handling for wakepy failures
    - Logging of keep-awake state changes
    - Guaranteed cleanup on exit (success, error, or interruption)
    - Graceful degradation if wakepy is unavailable
    
    Usage:
        with keep_awake_context():
            # Your long-running code here
            run_scan()
    
    Raises:
        Does not raise exceptions - logs errors and continues execution
    """
    if not WAKEPY_AVAILABLE:
        logger.warning('wakepy not available - continuing without keep-awake protection')
        logger.info('Install wakepy: pip install wakepy')
        yield
        return
    
    keep_awake_manager = None
    activation_successful = False
    
    try:
        # Attempt to activate keep-awake mode
        logger.info('Activating keep-awake mode...')
        keep_awake_manager = keep.running()
        keep_awake_manager.__enter__()
        activation_successful = True
        logger.info('✅ Keep-awake mode ACTIVE - system will not auto-sleep')
        logger.info('Note: Screen lock and screensaver remain enabled')
        
    except Exception as e:
        # Log activation failure but continue execution
        logger.error(f'Failed to activate keep-awake mode: {e}')
        logger.warning('Continuing scan without keep-awake protection')
        logger.info('Your system may sleep during the scan if power settings allow')
    
    try:
        # Yield control to the calling code
        yield
        
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        logger.info('Scan interrupted by user (Ctrl+C)')
        raise
        
    except Exception as e:
        # Log any errors during scan execution
        logger.error(f'Error during scan execution: {e}')
        raise
        
    finally:
        # Always attempt to deactivate keep-awake mode
        if activation_successful and keep_awake_manager is not None:
            try:
                logger.info('Deactivating keep-awake mode...')
                keep_awake_manager.__exit__(None, None, None)
                logger.info('✅ Keep-awake mode DEACTIVATED - system can now sleep normally')
                logger.info('Your system will follow normal power management settings')
                
            except Exception as e:
                # Log deactivation failure - this is critical
                logger.error(f'CRITICAL: Failed to deactivate keep-awake mode: {e}')
                logger.error('Your system may not sleep properly until restarted')
                logger.error('Workaround: Restart your system or manually adjust power settings')
                
                # Try to provide helpful troubleshooting info
                import platform
                os_name = platform.system()
                if os_name == 'Darwin':  # macOS
                    logger.info('macOS users: Check for caffeinate processes with: ps aux | grep caffeinate')
                elif os_name == 'Linux':
                    logger.info('Linux users: Check for active inhibitors with: systemd-inhibit --list')
                elif os_name == 'Windows':
                    logger.info('Windows users: Check Power & sleep settings or restart your PC')
        else:
            # Keep-awake was never activated, so nothing to clean up
            if not WAKEPY_AVAILABLE:
                logger.debug('Skipping keep-awake cleanup (wakepy not available)')
            else:
                logger.debug('Skipping keep-awake cleanup (was not activated)')


def test_keep_awake():
    """Test function to verify keep-awake functionality.
    
    Run this to check if wakepy is working correctly on your system.
    """
    import time
    
    print('Testing keep-awake functionality...')
    print('This will prevent sleep for 10 seconds, then allow it again.\n')
    
    try:
        with keep_awake_context():
            print('Keep-awake is now active.')
            print('Your system should NOT auto-sleep for the next 10 seconds...')
            for i in range(10, 0, -1):
                print(f'{i}...', flush=True)
                time.sleep(1)
            print('\nTest period completed.')
        
        print('\nKeep-awake has been deactivated.')
        print('Your system can now sleep normally.')
        print('✅ Test completed successfully!')
        
    except KeyboardInterrupt:
        print('\n\nTest interrupted by user.')
        print('Keep-awake cleanup should have executed.')
    except Exception as e:
        print(f'\n❌ Test failed with error: {e}')
        return False
    
    return True


if __name__ == '__main__':
    # Allow running this module directly to test functionality
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    
    print('Keep-Awake Module Test')
    print('=' * 60)
    
    if not WAKEPY_AVAILABLE:
        print('❌ wakepy is not installed')
        print('Install it with: pip install wakepy')
        sys.exit(1)
    
    success = test_keep_awake()
    sys.exit(0 if success else 1)
