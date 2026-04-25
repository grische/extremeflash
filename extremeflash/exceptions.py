"""Custom exceptions raised across the flash session.

Defined in their own module so:
  - serial-side helpers (PR 4a's `read_until` will live in `serial_console.py`)
    can import `OperationCancelled` without circular imports;
  - the FlashSession serial-thread wrapper can `isinstance(exc, OperationCancelled)`
    without pulling in the serial-console module.
"""


class OperationCancelled(Exception):
    """Raised by serial reads when the session's `cancel` Event is set mid-operation."""


class FlashError(RuntimeError):
    """Raised on unrecoverable flash conditions (e.g., bad initramfs image rejected
    by U-Boot) that should propagate out as a CLI failure with a clean cleanup path."""
