from collections import defaultdict
import ConfigParser
import os

class ARPModule:
    def __init__(self, config, messageBus):
        self.config = config
        self.messageBus = messageBus
        self.DAI = DynamicARPInspection(config, self)

    def packetIn(self, packet):
        if not packet.layer3.isARP():
            return

        try:
			pkt = packet.layer3.packet
			self.DAI.inspectARPPacket(pkt)
        except:
			self.module.messageBus.publish("Event.Log.Error", "Not properly formatted ARP packet")


class DynamicARPInspection:
    def __init__(self, config, module):
        self.config = config
        self.module = module
        self.previousArps = {}
        # check whether static ARP table is enabled
        self.static_arp_table = self.config.getboolean('ARPModule', 'static_arp_table')
        if self.static_arp_table:
            # configure static ARP table
            self.readStaticARPTable()

    def readStaticARPTable(self):
        # check whether file exists
        tableFile = self.config.get('ARPModule', 'table_file')
        if not os.path.isfile(tableFile):
            print 'Static ARP Table: %s does not exist' % tableFile
            exit(2)

        # read static ARP table configuration file
        tableConfig = ConfigParser.RawConfigParser()
        tableConfig.read(tableFile)

        # create a mapping of IP addresses to corresponding MAC address(es)
        self.mapping = defaultdict(list)
        mapping = tableConfig.options('Mappings')
        for IP in mapping:
            MACs = tableConfig.get('Mappings', IP).split(',')
            for MAC in MACs:
                MAC = MAC.strip()
                self.mapping[IP].append(MAC)


    def inspectARPPacket(self, pkt):
        # check for unusual host behavior
        self.checkDeviations(pkt)
        # check ARP requests
        if pkt.isRequest():
            self.info("%s [%s] sends ARP Request to %s [%s]" % (pkt.srcMAC, pkt.srcIP, pkt.dstMAC, pkt.dstIP))
            if pkt.isGratuitous():
                self.notice(pkt.srcIP, " transmits gratuitous ARP Request, claiming to be: ", pkt.srcMAC)
            if not pkt.isBroadcast():
                self.notice(pkt.srcIP, " sends ARP Request with destination other than broadcast address, namely: ", pkt.dstMAC)
        # check ARP replies
        elif pkt.isReply():
            self.info("%s [%s] sends ARP Reply to %s [%s]" % (pkt.srcMAC, pkt.srcIP, pkt.dstMAC, pkt.dstIP))
            if pkt.isBindingToBroadcast():
                self.error(pkt.srcIP, " is trying to bind to the broadcast address")
            if pkt.isBroadcast():
                self.notice(pkt.srcIP, " replies with broadcast address")
            if pkt.isGratuitous():
                self.notice(pkt.srcIP, " transmits gratuitous ARP Response, claiming to be: ", pkt.srcMAC)
            if self.static_arp_table and self.isInvalidBinding(pkt):
                self.notice(pkt.srcIP, " is trying to bind to a MAC address not in the static ARP table, namely: ", pkt.srcMAC)
        # other ARP opcodes are not supported by the DAI
        else:
            self.notice(pkt.srcIP, " transmits ARP packet with opcode other than request or reply: ", pkt.opcode)


    # check whether this packet contains an unknown IP,MAC combination
    def isInvalidBinding(self, pkt):
        if pkt.srcIP in self.mapping:
            if pkt.srcMAC in self.mapping[pkt.srcIP]:
                return False
        return True


    # check for unusual deviations in host behavior, 
    # that could hint at a potential implementation mistake
    def checkDeviations(self, pkt):
        # gratuitous arps are not interesting:
        # - nobody will reply, so it cannot be removed
        # - an earlier occurrence can mean the host reconnected to the network
        if pkt.isGratuitous():
            return

        if pkt.isRequest():
            # store the request
            pktID = "%s-%s" % (pkt.srcIP, pkt.dstIP)
            self.previousArps[pktID] = True

        elif pkt.isReply():
            pktID = "%s-%s" % (pkt.dstIP, pkt.srcIP)
            if pktID not in self.previousArps:
                # replies without a pending request means a potential implementation mistake
                self.notice(pkt.srcIP, " sends reply to %s, which does not have a pending request" % pkt.dstIP)
            else:
                # in case we have a pending request, the request can be removed
                self.previousArps.pop(pktID)
            

    # publish an info message on the bus
    def info(self, message):
        self.module.messageBus.publish("Event.Log.Info", message)

    # publish a notice message on the bus
    def notice(self, host, text, target = ''):
        message = host + text + target
        self.module.messageBus.publish("Event.Log.Notice", message)

    # publish a notice message on the bus
    def error(self, host, text, target = ''):
        message = host + text + target
        self.module.messageBus.publish("Event.Log.Error", message)

