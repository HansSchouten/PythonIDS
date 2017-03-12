class EthernetFrame:
    def __init__(self, buf):
        self.parse(buf)

    def parse(self, buf):
        # the first 14 bytes form the ethernet frame header
        self.srcMAC = buf.parseMAC()
        self.dstMAC = buf.parseMAC()
        self.etherType = buf.unpack("!H")[0]
