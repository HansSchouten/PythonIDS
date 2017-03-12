from parser.bytebuffer import PacketByteBuffer

from parser.packets.ethernetframe import EthernetFrame
from parser.packets.dnspacket import DNSPacket
from parser.packets.ippacket import IPPacket
from parser.packets.udppacket import UDPPacket
from parser.packets.arppacket import ARPPacket

class Packet:
    def __init__(self, data):
        buf = PacketByteBuffer(data)
        self.parse(buf)

    def parse(self, buf):
        self.layer2 = Layer2(buf)
        self.layer3 = Layer3(self.layer2, buf)
        self.layer4 = Layer4(self.layer3, buf)
        self.layer5 = Layer5(self.layer4, buf)
            

class Layer2:
    def __init__(self, buf):
        self.hasNothing = False
        self.frame = EthernetFrame(buf)

class Layer3:
    def __init__(self, layer2, buf):
        self.hasNothing = layer2.hasNothing
        self.layer2 = layer2
        if layer2.hasNothing:
            return
        self.parse(buf)

    def parse(self, buf):
        if self.isIP():
            self.packet = IPPacket(buf)
        elif self.isARP():
            self.packet = ARPPacket(buf)
        else:
            self.hasNothing = True
            print 'Unsupported packet at layer 3. Ethernet Type: %i' % self.layer2.frame.etherType

    def isIP(self):
        return self.layer2.frame.etherType == 0x0800

    def isARP(self):
        return self.layer2.frame.etherType == 0x0806

class Layer4:
    def __init__(self, layer3, buf):
        self.hasNothing = layer3.hasNothing
        self.layer3 = layer3
        if layer3.hasNothing:
            return
        self.parse(buf)

    def parse(self, buf):
        if self.isUDP():
            self.packet = UDPPacket(buf)
        else:
            self.hasNothing = True
            
    def isUDP(self):
        return self.layer3.isIP() and (self.layer3.packet.protocol == 17)

class Layer5:
    def __init__(self, layer4, buf):
        self.hasNothing = layer4.hasNothing
        self.layer4 = layer4
        if layer4.hasNothing:
            return
        self.parse(buf)

    def parse(self, buf):
        if self.isDNS():
            self.packet = DNSPacket(buf)
        else:
            self.hasNothing = True
            print 'Unsupported packet at layer 5'
            
    def isDNS(self):
        if self.layer4.hasNothing:
            return False
        return self.layer4.isUDP() and (
                self.layer4.packet.srcPort == 53 or
                self.layer4.packet.dstPort == 53
            )
