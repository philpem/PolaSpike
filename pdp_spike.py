from pydbg import *
from pydbg.defines import *
from struct import *
import utils, sys
#from ctypes import *
#from ctypes.wintypes import *

from scsi import *

### entry callback
# dbg: pydbg instance
# args: arguments on stack when hook was hit
def cb_entry_SendASPI32Command(dbg, args):
    return DBG_CONTINUE

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
    print "\tASPI return code=0x%02X\n\n" % x,
    #print dbg.dump_context()
    return DBG_CONTINUE


# Set a hook on a DLL function
def hook(dbg, dll, func, entry_cb, exit_cb = None):
    hook_addr = dbg.func_resolve_debuggee(dll, func)
    if hook_addr:
        hooks.add(dbg, hook_addr, 1, None, exit_cb)
    else:
        sys.exit(-1)

### Called when a DLL is loaded
# dbg: pydbg instance
def handle_load_dll(dbg):
    last_dll = dbg.get_system_dll(-1).name.lower()
    #print "DLL load: %s" % last_dll.name.lower()
    if last_dll == "wnaspi32.dll":
        # ASPI library in place.
        hook(dbg, last_dll, "SendASPI32Command", cb_entry_SendASPI32Command, cb_exit_SendASPI32Command)

    return DBG_CONTINUE

###################################################

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
