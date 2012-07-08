#-------------------------------------------------------------------------------
# Name:        scsi
# Purpose:     SCSI utilities
#
# Author:      Phil Pemberton
#
# Created:     08/07/2012
# Copyright:   (c) 2012 Phil Pemberton
# Licence:     GNU GPL V3
#-------------------------------------------------------------------------------

from struct import *

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

def SCSI_AspiStatusStr(code):
    """
    Decode an ASPI error code byte into a human-readable string
    """
    if code == SS_PENDING:
        return "Operation pending"
    elif code == SS_COMP:
        return "Operation complete"
    elif code == SS_ABORTED:
        return "Operation aborted"
    elif code == SS_ABORT_FAIL:
        return "Operation failed to abort"
    elif code == SS_ERR:
        return "Error condition"
    elif code == SS_INVALID_CMD:
        return "Invalid command"
    elif code == SS_INVALID_HA:
        return "Invalid Host Adapter number"
    elif code == SS_NO_DEVICE:
        return "No device"
    elif code == SS_INVALID_SRB:
        return "Invalid SRB"
    elif code == SS_BUFFER_ALIGN:
        return "Buffer alignment error"
    elif code == SS_SECURITY_VIOLATION:
        return "Security violation"
    elif code == SS_FAILED_INIT:
        return "ASPI failed to initialise"
    elif code == SS_BUFFER_TOO_BIG:
        return "Buffer too big"
    else:
        return "Unknown error"

def SCSI_DecodeSRB(dbg, addr):
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
