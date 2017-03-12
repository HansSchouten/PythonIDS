class UDPPacket:
    def __init__(self, buf):
        self.parse(buf)

    def parse(self, buf):
        # first 8 bytes are UDP packet header
        self.header = buf.unpack('!HHHH')
        self.srcPort = self.header[0]
        self.dstPort = self.header[1]
        self.length = self.header[2]
        self.checksum = self.header[3]
