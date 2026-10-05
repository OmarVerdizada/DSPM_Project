"""pysmb opens a file it reads without FILE_SHARE_DELETE (W2.3).

``SMBConnection.retrieveFileFromOffset`` creates its handle with share access READ |
WRITE only, so while a scan reads a file nobody can delete or rename it: a user saving
over a document in Office, or a job moving a file out of a drop folder, gets a sharing
violation for as long as the read lasts. The SMB 3 transport (``smb3_transport``)
already opens with FILE_SHARE_DELETE.

:func:`allow_delete_while_reading` makes pysmb do the same for every read-only open: an
open for FILE_OPEN whose access mask asks for no write, delete or permission change also
shares DELETE. An open that writes is left exactly as pysmb made it. Applied once, when
the SMB collector loads; ``DSPM_SMB_SHARE_DELETE=0`` leaves pysmb unchanged.
"""
from __future__ import annotations

import os

# Any of these in an access mask is an open that changes something.
_WRITE_ACCESS = (0x02 | 0x04 | 0x10 | 0x40 | 0x100   # data, append, EA, delete child, attributes
                 | 0x010000 | 0x040000 | 0x080000    # DELETE, WRITE_DAC, WRITE_OWNER
                 | 0x10000000 | 0x40000000)          # GENERIC_ALL, GENERIC_WRITE
_FILE_OPEN = 0x01
_SHARE_READ, _SHARE_WRITE, _SHARE_DELETE = 0x01, 0x02, 0x04


def read_only_share_access(access_mask: int, share_access: int, create_disp: int) -> int:
    """The share access a read-only open should ask for: its own, plus DELETE."""
    if create_disp == _FILE_OPEN and not (int(access_mask) & _WRITE_ACCESS) \
            and int(share_access) & (_SHARE_READ | _SHARE_WRITE) == (_SHARE_READ | _SHARE_WRITE):
        return int(share_access) | _SHARE_DELETE
    return int(share_access)


def allow_delete_while_reading() -> bool:
    """Patch pysmb's SMB2 CREATE so read-only opens share DELETE; returns whether it is applied."""
    if str(os.getenv("DSPM_SMB_SHARE_DELETE", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return False
    try:
        from smb import base
    except ModuleNotFoundError:
        return False
    original = base.SMB2CreateRequest
    if getattr(original, "_sentro_share_delete", False):
        return True

    class SharedDeleteCreateRequest(original):
        _sentro_share_delete = True

        def __init__(self, *args, **kwargs) -> None:
            if "share_access" in kwargs:
                kwargs["share_access"] = read_only_share_access(
                    kwargs.get("access_mask", 0), kwargs["share_access"], kwargs.get("create_disp", 0))
            super().__init__(*args, **kwargs)

    base.SMB2CreateRequest = SharedDeleteCreateRequest
    return True
