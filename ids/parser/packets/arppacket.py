class ARPPacket:
    def __init__(self, buf):
        self.parse(buf)

    def parse(self, buf):
        # 16 bits hardware type
        self.hardwareType = buf.unpack('!H')[0]
        # 16 bits protocol type
        self.protocolType = buf.unpack('!H')[0]
        # 8 bits hardware size
        self.hardwareSize = buf.unpack('!B')[0]
        # 8 bits protocol size
        self.protocolSize = buf.unpack('!B')[0]
        # 16 bits opcode
        self.opcode = buf.unpack('!H')[0]
        # 6 byte sender Hardware Address
        self.srcMAC = buf.parseMAC()
        # 4 byte sender IP Address
        self.srcIP = buf.parseIPv4()
        # 6 byte target Hardware Address
        self.dstMAC = buf.parseMAC()
        # 4 byte target IP Address
        self.dstIP = buf.parseIPv4()

    def isRequest(self):
        return self.opcode == 1

    def isReply(self):
        return self.opcode == 2

    def isGratuitous(self):
        return self.srcIP == self.dstIP

    def isBindingToBroadcast(self):
        return self.isReply() and self.srcMAC == 'ff:ff:ff:ff:ff:ff'

    def isBroadcast(self):
        return self.dstMAC == 'ff:ff:ff:ff:ff:ff'
