class DNSModule:
    def __init__(self, config, messageBus):
        self.config = config
        self.messageBus = messageBus

    def packetIn(self, packet):
        if not packet.layer5.isDNS():
            return

        print packet.layer5.packet
