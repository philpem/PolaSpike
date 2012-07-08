from pydbg import *
from pydbg.defines import *
from struct import *
import utils, sys
#from ctypes import *
#from ctypes.wintypes import *

SC_HA_INQUIRY = 0x01
SC_GET_DEV_TYPE = 0x01
SC_EXEC_SCSI_CMD = 0x02
SC_ABORT_SRB = 0x03
SC_RESET_DEV = 0x04
SC_GET_DISK_INFO = 0x06

SS_PENDING = 0x00
SS_COMP = 0x01
SS_ABORTED = 0x02
SS_ABORT_FAIL = 0x03
SS_ERR = 0x04
SS_INVALID_CMD = 0x80
SS_INVALID_HA = 0x81
SS_NO_DEVICE = 0x82
SS_INVALID_SRB = 0xE0
SS_BUFFER_ALIGN = 0xE1
SS_SECURITY_VIOLATION = 0xE2
SS_FAILED_INIT = 0xE3
SS_BUFFER_TOO_BIG = 0xE6

def DecodeSRB(dbg, addr):
    # read the SRB header
    mem = dbg.read_process_memory(addr, 8)
    srb_hdr = dict(zip(
        ("SRB_Cmd", "SRB_Status", "SRB_HaId", "SRB_Flags", "SRB_Reserved"),
        unpack("BBBBL", mem))
    )

    if srb_hdr['SRB_Cmd'] == SC_EXEC_SCSI_CMD:
        # SRB is a SCSI Cmd Exec request
        mem = dbg.read_process_memory(addr+8, 20)
        srb = dict(zip((
            "SRB_Target",
            "SRB_Lun",
            "SRB_Rsvd1",
            "SRB_BufLen",
            "SRB_BufPtr",
            "SRB_SenseLen",
            "SRB_CDBLen",
            "SRB_HaStat",
            "SRB_TargStat",
            "SRB_PostProc"),
            unpack("BBHLLBBBBL", mem))
        )
        #print srb_hdr
        #print srb

        # decode SCB direction
        if (srb_hdr and 0x08):
            dir = "IN"
        elif (srb_hdr and 0x10):
            dir = "OUT"
        else:
            dir = "unknown!"

        print "HA/TA/LUN %d:%d:%d   SC_EXEC_SCSI_CMD   %s" % (srb_hdr['SRB_HaId'], srb['SRB_Target'], srb['SRB_Lun'], dir)
        cdb = dbg.read_process_memory(addr+48, srb['SRB_CDBLen'])
        buf = dbg.read_process_memory(srb['SRB_BufPtr'], srb['SRB_BufLen'])
        print "\tCDB   (%4d): %s" % (len(cdb), dbg.hex_dump(cdb, prefix="\t\t")[2:]),
        print "\tBUF   (%4d): %s" % (len(buf), dbg.hex_dump(buf, prefix="\t\t")[2:]),

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
    DecodeSRB(dbg, args[0])
    print "\tASPI return code=0x%02X\n\n" % x,
    #print dbg.dump_context()
    return DBG_CONTINUE


# Set a hook on a DLL function
def hook(dbg, dll, func, entry_cb, exit_cb = None):
    hook_addr = dbg.func_resolve_debuggee(dll, func)
    if hook_addr:
        hooks.add(dbg, hook_addr, 1, entry_cb, exit_cb)
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
