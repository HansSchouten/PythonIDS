class IPPacket:
    def __init__(self, buf):
        self.parse(buf)

    def parse(self, buf):
        # determine IP header length (4 least significant bits of first byte)
        first_byte = buf.unpack("!B")
        self.header_length = (first_byte[0] & 0xF) * 4       
        headerBuf = buf.clone() 
        buf.skip(self.header_length)
        self.tos = headerBuf.unpack("!B")[0]
        self.totalLength = headerBuf.unpack("!H")[0]
        self.identification = headerBuf.unpack("!H")[0]
        self.flags_and_offset = headerBuf.unpack("!H")[0]
        self.ttl = headerBuf.unpack("!B")[0]
        self.protocol = headerBuf.unpack("!B")[0]
        self.srcIP = headerBuf.parseIPv4()
        self.dstIP = headerBuf.parseIPv4()
