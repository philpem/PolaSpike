from pydbg import *
from pydbg.defines import *
from struct import *
import utils, sys
#from ctypes import *
#from ctypes.wintypes import *

from scsi import *

################################################################################

"""
### entry callback
# dbg: pydbg instance
# args: arguments on stack when hook was hit
def cb_entry(dbg, args):
    return DBG_CONTINUE

### exit callback
# dbg: pydbg instance
# args: arguments on stack when hook was hit
# ret: value in EAX register
def cb_exit(dbg, args, ret):
    return DBG_CONTINUE
"""

################################################################################
## CALLBACKS -- ASPI
################################################################################

### exit callback
# dbg: pydbg instance
# args: arguments on stack when hook was hit
# ret: value in EAX register
def cb_exit_SendASPI32Command(dbg, args, ret):
    if (ret == SS_PENDING):
        # Status is PENDING. Poll for transaction completion.
        x = SS_PENDING
        while x != SS_COMP:
            x = unpack("B", dbg.read_process_memory(args[0]+1, 1))[0]
    else:
        # Set 'x' to the ASPI response code
        x = ret
    SCSI_DecodeSRB(dbg, args[0])
    print "\tASPI return code=0x%02X (%s)\n\n" % (x, SCSI_AspiStatusStr(x)),
    #print dbg.dump_context()
    return DBG_CONTINUE

################################################################################
## CALLBACKS -- POLAROID PFR LIBRARY
################################################################################

def cb_entry_pfr_DP_ExposureWarning(dbg, args):
    print ">>> ENTRY: DP_ExposureWarning:, args=", args
    #print dbg.dump_context()
    return DBG_CONTINUE

def cb_exit_pfr_DP_ExposureWarning(dbg, args, ret):
    print "<<< EXIT:  DP_ExposureWarning, ret=", ret
    #print dbg.dump_context()
    return DBG_CONTINUE


def cb_entry_pfr_DP_DownLoadFilms(dbg, args):
    print ">>> ENTRY: DP_DownLoadFilms, args=", args
    #print dbg.dump_context()
    return DBG_CONTINUE

def cb_exit_pfr_DP_DownLoadFilms(dbg, args, ret):
    print "<<< EXIT:  DP_DownLoadFilms, ret=", ret
    #print dbg.dump_context()
    return DBG_CONTINUE

################################################################################

# Set a hook on a DLL function
def hook(dbg, dll, func, nparams, entry_cb, exit_cb = None):
    print ">>> Hooking ", dll, ":", func, "with ", nparams, " args"
    hook_addr = dbg.func_resolve_debuggee(dll, func)
    if hook_addr:
        hooks.add(dbg, hook_addr, nparams, entry_cb, exit_cb)
    else:
        print "!!! Couldn't resolve address of %s in %s!" % (func, dll)

### Called when a DLL is loaded
# dbg: pydbg instance
def handle_load_dll(dbg):
    last_dll = dbg.get_system_dll(-1).name.lower()
    print "DLL load: %s" % last_dll
    if last_dll == "wnaspi32.dll":
        # ASPI DLL just loaded... set the BPs
        print "ASPI DLL loaded"
        hook(dbg, last_dll, "SendASPI32Command", 1, None, cb_exit_SendASPI32Command)

    elif last_dll == "pfr.dll":
        # Polaroid Palette DLL just loaded... set the BPs
        hook(dbg, last_dll, "_DP_DownLoadFilms", 0, cb_entry_pfr_DP_DownLoadFilms, cb_exit_pfr_DP_DownLoadFilms)
        hook(dbg, last_dll, "_DP_ExposureWarning@4", 1, cb_entry_pfr_DP_ExposureWarning, cb_exit_pfr_DP_ExposureWarning)

    return DBG_CONTINUE

################################################################################

# Initialise PyDbg
dbg = pydbg()
hooks = utils.hook_container()

# Load the target
dbg.load("C:\Adobe\Photoshop\photoshp.exe")

# Set a callback on DLL load
# Essentially what we're doing is waiting for one of our target DLLs to load,
# then setting up our breakpoints in the callback.
dbg.set_callback(LOAD_DLL_DEBUG_EVENT, handle_load_dll)

# Launch our victim
dbg.run()
