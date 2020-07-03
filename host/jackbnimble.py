#!/usr/bin/python3

import time
import argparse
import binascii
import sys
import struct
from signal import signal, SIGINT
from threading import Thread, Lock, Timer
import bluetooth._bluetooth as _bt

from pocs import *

OGF_LE_CTL = 0x08

OCF_LE_SET_ADV_PARAMS = 0x06
OCF_LE_SET_EXT_ADV_PARAMS = 0x36

OCF_VS_ENABLE_CUSTOM_AC_PDU = 0x101
OCF_VS_SEND_AC_PDU_PAYLOAD = 0x102
OCF_VS_SEND_AC_PDU_HEADER = 0x103

EVT_LE_META_EVENT = 0x3E

ERR_HCI_COMMAND_DISALLOWED = 0x0C

def bdaddr2bin(str_bdaddr):
    str_bdaddr = "".join(str_bdaddr.split(':')[::-1])
    return binascii.unhexlify(str_bdaddr)

def to_opcode(ogf, ocf):
    return (ogf & 0x3F) << 10 | (ocf & 0x3FF)

def print_binstr(pkt):
    formatted = " ".join(["{:02x}".format(x) for x in pkt])
    print(formatted)
    return formatted

def is_cmd_status_ok(hci_sock, sent_opcode):
    succeeded = False
    print("is_cmd_status_ok: Waiting for opcode %x" % (sent_opcode))

    while True:
        status = None
        cmd_opcode = None

        try:
            pkt = hci_sock.recv(255)
        except:
            break;

        evt_code = pkt[1]
        print("is_cmd_status_ok: received evt_code 0x%x" % evt_code)

        if evt_code == _bt.EVT_CMD_COMPLETE:
            _, cmd_opcode, status = struct.unpack("<BHB", pkt[3:7])
            print('is_cmd_status_ok: got status - cmd_opcode %x, status %d' % (cmd_opcode, status))

            if cmd_opcode == sent_opcode:
                if status == 0:
                    succeeded = True

                return succeeded

    print('is_cmd_status_ok: failed ')
    return succeeded

class SessionManager():
    def __init__(self):
        self.init_argparser()
        self.init_poc_modules()

    def init_argparser(self):
        self.parser = argparse.ArgumentParser(description='JackBNimBLE Host')

        self.parser.add_argument("-i", '--hci_id', type=int, default=0,
                    help='hci interface number to use (default: 0)')

        self.subparsers = self.parser.add_subparsers(help='Select a command to execute', metavar="<command>")
        self.subparsers.required = True
        self.subparsers.dest = 'command'

    def init_poc_modules(self):
        pocs_mods_keys = [x for x in sys.modules.keys() if x.startswith('pocs.')]
        pocs_mods = [sys.modules[x] for x in pocs_mods_keys]

        self.pm_dict = {}
        for pm in pocs_mods:
            ts = pm.TestSet(self.subparsers)
            self.pm_dict[ts.getCmd()] = ts

        self.args = self.parser.parse_args()

    def run(self):
        hm = HCIManager(self.args.hci_id)
        self.pm_dict[self.args.command].run(hm, self.args.action)

class HCIManager():
    def __init__(self, hci_id):
        self.timeout = 10
        self.handle = None
        self.hci_sock = None
        self.__is_alive = False
        self.hci_id = None
        self.cm = None
        self.called_adv_func = None

        self.hci_id = hci_id

        self.hci_sock = _bt.hci_open_dev(self.hci_id)
        self.hci_sock.settimeout(5)

        self.old_filter = self.hci_sock.getsockopt( _bt.SOL_HCI, _bt.HCI_FILTER, 14)

        signal(SIGINT, self.stop)

    def __del__(self):
        # restore old filter
        self.hci_sock.setsockopt(_bt.SOL_HCI, _bt.HCI_FILTER, self.old_filter)
        self.hci_sock.close()

    def set_filter(self, event_type = None, ogf = None, ocf = None):
        flt = _bt.hci_filter_new()
        _bt.hci_filter_set_ptype(flt, _bt.HCI_EVENT_PKT)

        if event_type:
            _bt.hci_filter_set_event(flt, event_type)
            if event_type == _bt.EVT_CMD_COMPLETE and ogf and ocf:
                _bt.hci_filter_set_opcode(flt, _bt.cmd_opcode_pack(ogf, ocf))
        else:
            _bt.hci_filter_all_events(flt)

        self.hci_sock.setsockopt(_bt.SOL_HCI, _bt.HCI_FILTER, flt)

    def set_adv_params(self):
        params = b"\x20\x00"                     # Advertising_Interval_Min
        params += b"\x20\x00"                    # Advertising_Interval_Max
        params += b"\x03"                        # Advertising_Type
        params += b"\x00"                        # Own_Address_Type
        params += b"\x00"                        # Peer_Address_Type
        params += b"\x00\x00\x00\x00\x00\x00"    # Peer_Address
        params += b"\x07"                        # Advertising_Channel_Map
        params += b"\x00"                        # Advertising_Filter_Policy

        # TODO: improve error handling
        _bt.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_ADV_PARAMS, params)
        is_cmd_status_ok(self.hci_sock, to_opcode(OGF_LE_CTL, OCF_LE_SET_ADV_PARAMS))

    def set_ext_adv_params(self):
        params = b"\x00"                         # Advertising_Handle
        params += b"\x00\x00"                    # Advertising_Event_Properties
        params += b"\x00\x01\x00"                # Primary_Advertising_Interval_Min
        params += b"\x00\x01\x00"                # Primary_Advertising_Interval_Max
        params += b"\x07"                        # Primary_Advertising_Channel_Map
        params += b"\x00"                        # Own_Address_Type
        params += b"\x01"                        # Peer_Address_Type
        params += b"\x00\x00\x00\x00\x00\x00"    # Peer_Address
        params += b"\x00"                        # Advertising_Filter_Policy
        params += b"\x00"                        # Advertising_Tx_Power
        params += b"\x01"                        # Primary_Advertising_PHY
        params += b"\x00"                        # Secondary_Advertising_Max_Skip
        params += b"\x01"                        # Secondary_Advertising_PHY
        params += b"\x01"                        # Advertising_SID
        params += b"\x00"                        # Scan_Request_Notification_Enable

        # TODO: improve error handling
        _bt.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_EXT_ADV_PARAMS, params)
        is_cmd_status_ok(self.hci_sock, to_opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_PARAMS))

    def enable_adv(self, enable, wait_status = True):
        OCF_LE_SET_ADV_ENABLE = 0x0a
        if enable:
            enable = b"\x01"
        else:
            enable = b"\x00"

        self.called_adv_func = self.enable_adv

        _bt.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_ADV_ENABLE, enable)
        if wait_status:
            is_cmd_status_ok(self.hci_sock, to_opcode(OGF_LE_CTL, OCF_LE_SET_ADV_ENABLE))

    def enable_ext_adv(self, enable, wait_status = True):
        OCF_LE_SET_EXT_ADV_ENABLE = 0x39
        if enable:
            enable = b"\x01"
        else:
            enable = b"\x00"

        self.called_adv_func = self.enable_ext_adv

        params = enable                 # Enable
        params += b"\x01"               # Number_of_Sets
        params += b"\x00"               # Advertising_Handle[i]
        params += b"\x00\x00"           # Duration[i]
        params += b"\x00"               # Max_Extended_Advertising_Events[i]

        print(repr(params))
        _bt.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_EXT_ADV_ENABLE, params)
        if wait_status:
            is_cmd_status_ok(self.hci_sock, to_opcode(OGF_LE_CTL, OCF_LE_SET_EXT_ADV_ENABLE))

    def enable_custom_ac_pdu(self, enable, wait_status = True):
        if enable:
            enable = b"\x01\x00\x00"
        else:
            enable = b"\x00"

        _bt.hci_send_cmd(self.hci_sock, _bt.OGF_VENDOR_CMD, OCF_VS_ENABLE_CUSTOM_AC_PDU, enable)
        if wait_status:
            is_cmd_status_ok(self.hci_sock, to_opcode( _bt.OGF_VENDOR_CMD, OCF_VS_ENABLE_CUSTOM_AC_PDU))

    def send_ac_pdu_header(self, pdu_lsb):
        params = b"" + struct.pack("B", pdu_lsb)

        _bt.hci_send_cmd(self.hci_sock, _bt.OGF_VENDOR_CMD, OCF_VS_SEND_AC_PDU_HEADER, params)
        is_cmd_status_ok(self.hci_sock, to_opcode( _bt.OGF_VENDOR_CMD, OCF_VS_SEND_AC_PDU_HEADER))

    def send_ac_pdu_payload(self, pdu, wait):
        _bt.hci_send_cmd(self.hci_sock, _bt.OGF_VENDOR_CMD, OCF_VS_SEND_AC_PDU_PAYLOAD, pdu)
        is_cmd_status_ok(self.hci_sock, to_opcode( _bt.OGF_VENDOR_CMD, OCF_VS_SEND_AC_PDU_PAYLOAD))

        if wait:
            self.wait_for_ac_next_pdu()

    def wait_for_ac_next_pdu(self):
        print("Waiting for AC next pdu event")

        BT_HCI_EVT_VS_AC_NEXT_PDU = 0x10

        while True:
            pkt = self.hci_sock.recv(255)
            evt_code = pkt[1]
            print("wait_for_ac_next_pdu: received evt_code %x" % evt_code)

            if evt_code == _bt.EVT_VENDOR:
                subevent = pkt[3]
                if subevent == BT_HCI_EVT_VS_AC_NEXT_PDU:
                    return

    def cleanup(self):
        if self.called_adv_func:
            self.called_adv_func(False, False)

    def stop(self, signal_received, frame):
        self.enable_custom_ac_pdu(False, False)
        time.sleep(1)
        self.cleanup()

        sys.exit(0)

def main():
    smgr = SessionManager()
    smgr.run()

if __name__ == "__main__":
    main()
