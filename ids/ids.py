import getopt, datetime, sys, os
import ConfigParser

from scapy.all import PcapWriter
from scapy.all import sniff
from dpkt import pcap
from messagebus import MessageBus
from parser.packetparser import Packet
from modules.logger import IDSLogger
from modules.dnsmodule import DNSModule
from modules.arpmodule import ARPModule

def main(argv):
    # default settings
    configFile = "ids.conf"

    # parse command line arguments
    try:
        opts, args = getopt.getopt(argv[1:],"ho:v",["config="])
    except getopt.GetoptError as err:
        print str(err)
        print 'usage: %s --config <configFile>' % argv[0]
        exit(2)
    for o, a in opts:
        if o == '--config':
            configFile = a

    # instantiate IDS
    ids = IntrusionDetectionSystem(configFile)
    ids.start()


class IntrusionDetectionSystem:
    def __init__(self, configFile):
        if not os.path.isfile(configFile):
            print 'Config file: %s does not exist' % configFile
            exit(2)
        # read config file
        self.config = ConfigParser.RawConfigParser()
        self.config.read(configFile)
        self.configMode = self.config.get('Global', 'operation_mode')
        # init message bus, logger and modules
        self.messageBus = MessageBus()
        self.logger = IDSLogger(self.config, self.messageBus)
        self.registerModules()

    def registerModules(self):
        self.modules = []
        # all supported modules
        allModules = ['DNSModule', 'ARPModule']
        # add objects of all enabled modules to the modules list
        for module in allModules:
            if self.config.getboolean(module, 'enabled'):
                # create object from module string
                moduleObject = getattr(sys.modules[__name__], module)(self.config, self.messageBus)
                # add module to list of active modules
                self.modules.append(moduleObject)

    def start(self):
        if self.configMode == 'sniffer':
            # instantiate a pcap sniffer
            idsInput = IDSPcapSniffer(self.config)
            # call packetIn for each captured packet
            idsInput.start(self.packetIn)
        elif self.configMode == 'reader':
            # instantiate a pcap reader
            idsInput = IDSPcapReader(self.config)
            # call packetIn for each packet in pcap file
            idsInput.start(self.packetIn)
        else:
            print 'Intrusion Detection System only supports `sniffer` or `reader` operation modes'
            exit(2)

    def packetIn(self, packetData):
        # print raw data
        if self.config.getboolean('Global', 'dump_raw_packets'):
            hexdump(packetData)
            print "\n"

        # use packetparser.py to parse raw data into a Packet object
        packet = Packet(packetData)

        # relay packet to all enabled modules
        for module in self.modules:
            module.packetIn(packet)


class IDSPcapReader:
    def __init__(self, config):
        self.config = config
        self.pause = config.getboolean('Reader', 'pause')

    def start(self, callback):
        # read pcap file
        filePath = self.config.get('Reader', 'input_file')
        fileContents = open(filePath)
        pcapFile = pcap.Reader(fileContents)
        # parse all lines of pcap file
        for timestamp, data in pcapFile:
            callback(data)
            if self.pause:
                raw_input("Press Enter to continue...")
        print 'End of input file reached'

class IDSPcapSniffer:
    def __init__(self, config):
        self.config = config

    def start(self, callback):
        # create an sniffer output file, if needed
        self.logPackets = self.config.getboolean('Sniffer', 'log_packets')
        if self.logPackets:
            outputFile = self.config.get('Sniffer', 'output_file')
            self.pcapWriter = PcapWriter(outputFile, append=False, sync=True)
        # start sniffing with the given filter and callback,
        # the appropriate filter will be applied within each module
        self.callback = callback
        interface = self.config.get('Sniffer', 'interface')
        sniff(iface=interface, filter='', prn=self.__snifferCallback)

    def __snifferCallback(self, packet):
        # append output file with packet
        if self.logPackets:
            self.pcapWriter.write(packet)
        # parse packet
        self.callback(str(packet))


if __name__ == "__main__":
    main(sys.argv)
