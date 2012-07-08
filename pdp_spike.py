from pydbg import *
from pydbg.defines import *
from struct import *
import utils, sys
#from ctypes import *
#from ctypes.wintypes import *

from scsi import *

################################################################################

# Set to true to display CPU state when entering or exiting a PFR function
DBG_PRINT_STATE = False

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
        while x == SS_PENDING:
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

def cb_entry_pfr__DP_DownLoadFilms(dbg, args):
	print ">>> ENTRY: _DP_DownLoadFilms, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_DownLoadFilms(dbg, args, ret):
	print "<<< EXIT:  _DP_DownLoadFilms, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_ExposureWarning(dbg, args):
	print ">>> ENTRY: _DP_ExposureWarning, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_ExposureWarning(dbg, args, ret):
	print "<<< EXIT:  _DP_ExposureWarning, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_FirmWareBurn(dbg, args):
	print ">>> ENTRY: _DP_FirmWareBurn, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_FirmWareBurn(dbg, args, ret):
	print "<<< EXIT:  _DP_FirmWareBurn, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_FirmWareLoad(dbg, args):
	print ">>> ENTRY: _DP_FirmWareLoad, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_FirmWareLoad(dbg, args, ret):
	print "<<< EXIT:  _DP_FirmWareLoad, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_FirmWareStart(dbg, args):
	print ">>> ENTRY: _DP_FirmWareStart, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_FirmWareStart(dbg, args, ret):
	print "<<< EXIT:  _DP_FirmWareStart, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_GetPrinterStatus(dbg, args):
	print ">>> ENTRY: _DP_GetPrinterStatus, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_GetPrinterStatus(dbg, args, ret):
	print "<<< EXIT:  _DP_GetPrinterStatus, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_InitPrinter(dbg, args):
	print ">>> ENTRY: _DP_InitPrinter, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_InitPrinter(dbg, args, ret):
	print "<<< EXIT:  _DP_InitPrinter, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_InqBlockMode(dbg, args):
	print ">>> ENTRY: _DP_InqBlockMode, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_InqBlockMode(dbg, args, ret):
	print "<<< EXIT:  _DP_InqBlockMode, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_Pacing(dbg, args):
	print ">>> ENTRY: _DP_Pacing, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_Pacing(dbg, args, ret):
	print "<<< EXIT:  _DP_Pacing, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_ResetToDefault(dbg, args):
	print ">>> ENTRY: _DP_ResetToDefault, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_ResetToDefault(dbg, args, ret):
	print "<<< EXIT:  _DP_ResetToDefault, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_SendImageBlock(dbg, args):
	print ">>> ENTRY: _DP_SendImageBlock, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_SendImageBlock(dbg, args, ret):
	print "<<< EXIT:  _DP_SendImageBlock, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_SendImageData(dbg, args):
	print ">>> ENTRY: _DP_SendImageData, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_SendImageData(dbg, args, ret):
	print "<<< EXIT:  _DP_SendImageData, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_SendPrinterParams(dbg, args):
	print ">>> ENTRY: _DP_SendPrinterParams, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_SendPrinterParams(dbg, args, ret):
	print "<<< EXIT:  _DP_SendPrinterParams, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_ShutDown(dbg, args):
	print ">>> ENTRY: _DP_ShutDown, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_ShutDown(dbg, args, ret):
	print "<<< EXIT:  _DP_ShutDown, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_StartExposure(dbg, args):
	print ">>> ENTRY: _DP_StartExposure, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_StartExposure(dbg, args, ret):
	print "<<< EXIT:  _DP_StartExposure, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_TerminateExposure(dbg, args):
	print ">>> ENTRY: _DP_TerminateExposure, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_TerminateExposure(dbg, args, ret):
	print "<<< EXIT:  _DP_TerminateExposure, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_doscsi_cmd(dbg, args):
	print ">>> ENTRY: _DP_doscsi_cmd, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_doscsi_cmd(dbg, args, ret):
	print "<<< EXIT:  _DP_doscsi_cmd, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_firmware_rev(dbg, args):
	print ">>> ENTRY: _DP_firmware_rev, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_firmware_rev(dbg, args, ret):
	print "<<< EXIT:  _DP_firmware_rev, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_scsi_init(dbg, args):
	print ">>> ENTRY: _DP_scsi_init, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_scsi_init(dbg, args, ret):
	print "<<< EXIT:  _DP_scsi_init, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__DP_scsi_inq(dbg, args):
	print ">>> ENTRY: _DP_scsi_inq, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__DP_scsi_inq(dbg, args, ret):
	print "<<< EXIT:  _DP_scsi_inq, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__FilmTableName(dbg, args):
	print ">>> ENTRY: _FilmTableName, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__FilmTableName(dbg, args, ret):
	print "<<< EXIT:  _FilmTableName, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__NumberFilmTables(dbg, args):
	print ">>> ENTRY: _NumberFilmTables, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__NumberFilmTables(dbg, args, ret):
	print "<<< EXIT:  _NumberFilmTables, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__ToolKitLog(dbg, args):
	print ">>> ENTRY: _ToolKitLog, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__ToolKitLog(dbg, args, ret):
	print "<<< EXIT:  _ToolKitLog, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_entry_pfr__firmware_rev(dbg, args):
	print ">>> ENTRY: _firmware_rev, args %s" % args
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

def cb_exit_pfr__firmware_rev(dbg, args, ret):
	print "<<< EXIT:  _firmware_rev, args %s, return %d" % (args, ret)
	if DBG_PRINT_STATE:
		print dbg.dump_context()
	return DBG_CONTINUE

################################################################################

# Set a hook on a DLL function
def hook(dbg, dll, func, nparams, entry_cb, exit_cb = None):
    #print ">>> Hooking ", dll, ":", func, "with ", nparams, " args"
    hook_addr = dbg.func_resolve_debuggee(dll, func)
    if hook_addr:
        hooks.add(dbg, hook_addr, nparams, entry_cb, exit_cb)
    else:
        print "!!! ERROR [hook]: Couldn't resolve address of %s in %s!" % (func, dll)

### Called when a DLL is loaded
# dbg: pydbg instance
def handle_load_dll(dbg):
    last_dll = dbg.get_system_dll(-1).name.lower()
    # print "DLL load: %s" % last_dll
    if last_dll == "wnaspi32.dll":
        # ASPI DLL just loaded... set the BPs
        print "ASPI DLL loaded"
        hook(dbg, "wnaspi32.dll", "SendASPI32Command", 1, None, cb_exit_SendASPI32Command)

        #elif last_dll == "pfr.dll":
        # Polaroid Palette DLL just loaded... set the BPs
        hook(dbg, "pfr.dll", "_DP_DownLoadFilms@12", 3, cb_entry_pfr__DP_DownLoadFilms, cb_exit_pfr__DP_DownLoadFilms)
        hook(dbg, "pfr.dll", "_DP_ExposureWarning@4", 1, cb_entry_pfr__DP_ExposureWarning, cb_exit_pfr__DP_ExposureWarning)
        hook(dbg, "pfr.dll", "_DP_FirmWareBurn@4", 1, cb_entry_pfr__DP_FirmWareBurn, cb_exit_pfr__DP_FirmWareBurn)
        hook(dbg, "pfr.dll", "_DP_FirmWareLoad@8", 2, cb_entry_pfr__DP_FirmWareLoad, cb_exit_pfr__DP_FirmWareLoad)
        hook(dbg, "pfr.dll", "_DP_FirmWareStart@8", 2, cb_entry_pfr__DP_FirmWareStart, cb_exit_pfr__DP_FirmWareStart)
        hook(dbg, "pfr.dll", "_DP_GetPrinterStatus@8", 2, cb_entry_pfr__DP_GetPrinterStatus, cb_exit_pfr__DP_GetPrinterStatus)
        hook(dbg, "pfr.dll", "_DP_InitPrinter@12", 3, cb_entry_pfr__DP_InitPrinter, cb_exit_pfr__DP_InitPrinter)
        hook(dbg, "pfr.dll", "_DP_InqBlockMode@8", 2, cb_entry_pfr__DP_InqBlockMode, cb_exit_pfr__DP_InqBlockMode)
        hook(dbg, "pfr.dll", "_DP_Pacing@8", 2, cb_entry_pfr__DP_Pacing, cb_exit_pfr__DP_Pacing)
        hook(dbg, "pfr.dll", "_DP_ResetToDefault@4", 1, cb_entry_pfr__DP_ResetToDefault, cb_exit_pfr__DP_ResetToDefault)
        hook(dbg, "pfr.dll", "_DP_SendImageBlock@24", 6, cb_entry_pfr__DP_SendImageBlock, cb_exit_pfr__DP_SendImageBlock)
        hook(dbg, "pfr.dll", "_DP_SendImageData@20", 5, cb_entry_pfr__DP_SendImageData, cb_exit_pfr__DP_SendImageData)
        hook(dbg, "pfr.dll", "_DP_SendPrinterParams@4", 1, cb_entry_pfr__DP_SendPrinterParams, cb_exit_pfr__DP_SendPrinterParams)
        hook(dbg, "pfr.dll", "_DP_ShutDown@4", 1, cb_entry_pfr__DP_ShutDown, cb_exit_pfr__DP_ShutDown)
        hook(dbg, "pfr.dll", "_DP_StartExposure@4", 1, cb_entry_pfr__DP_StartExposure, cb_exit_pfr__DP_StartExposure)
        hook(dbg, "pfr.dll", "_DP_TerminateExposure@8", 2, cb_entry_pfr__DP_TerminateExposure, cb_exit_pfr__DP_TerminateExposure)
        hook(dbg, "pfr.dll", "_DP_doscsi_cmd@28", 7, cb_entry_pfr__DP_doscsi_cmd, cb_exit_pfr__DP_doscsi_cmd)
        hook(dbg, "pfr.dll", "_DP_firmware_rev@4", 1, cb_entry_pfr__DP_firmware_rev, cb_exit_pfr__DP_firmware_rev)
        hook(dbg, "pfr.dll", "_DP_scsi_init@4", 1, cb_entry_pfr__DP_scsi_init, cb_exit_pfr__DP_scsi_init)
        hook(dbg, "pfr.dll", "_DP_scsi_inq@4", 1, cb_entry_pfr__DP_scsi_inq, cb_exit_pfr__DP_scsi_inq)
        hook(dbg, "pfr.dll", "_FilmTableName@12", 3, cb_entry_pfr__FilmTableName, cb_exit_pfr__FilmTableName)
        hook(dbg, "pfr.dll", "_NumberFilmTables@4", 1, cb_entry_pfr__NumberFilmTables, cb_exit_pfr__NumberFilmTables)
        hook(dbg, "pfr.dll", "_ToolKitLog@8", 2, cb_entry_pfr__ToolKitLog, cb_exit_pfr__ToolKitLog)
        hook(dbg, "pfr.dll", "_firmware_rev@4", 1, cb_entry_pfr__firmware_rev, cb_exit_pfr__firmware_rev)

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
