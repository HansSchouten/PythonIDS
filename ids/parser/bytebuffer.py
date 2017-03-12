from struct import *
import binascii, socket

'''
This class is a wrapper around the byte array.
It allows the byte array to be passed by reference to other methods.
The class supports the use of pointers (used in DNS packets)
It also provides a number of helper methods for parsing IP and MAC addresses
'''
class PacketByteBuffer:
    def __init__(self, data):
        self.all_data = data
        self.data = data

    # unpack raw data from the buffer with the given format
    def unpack(self, formatString, skip = True):
        length = calcsize(formatString)
        result = unpack(formatString, self.data[0:length])
        if skip:
            self.data = self.data[length:]
        return result

	# skip a number of positions in the bytearray
    def skip(self, length):
        self.data = self.data[length-1:]

	# clone the bytearray, at the current position or with all data
    def clone(self, cloneAllData = False):
        if cloneAllData:
            return PacketByteBuffer(self.all_data)            
        else:
            return PacketByteBuffer(self.data)

	# point to different location in array
    def point(self, index):
        self.data = self.all_data[index:]

    # return ipv4 address
    def parseIPv4(self):
        return socket.inet_ntoa(self.unpack('!4s')[0])

    # return MAC address
    def parseMAC(self):
        hexString = binascii.hexlify(self.unpack('!6s')[0])
        formatted = ':'.join(s.encode('hex') for s in hexString.decode('hex'))
        return formatted
