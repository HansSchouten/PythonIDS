class DNSPacket:
    types = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 11:'WKS', 12:'PTR', 15:'MX', 33:'SRV', 28:'AAAA', 255:'ANY'}

    def __init__(self, buf):
        buf = buf.clone()
        self.parse(buf)

    def parseBody(self, buf):
        self.questions = []
        self.str_questions = []
        for i in range(0, self.header.questionCount):
            question = DNSQuestion(buf)
            self.questions.append(question)
            self.str_questions.append(str(question))

        self.answers = []
        self.str_answers = []
        for i in range(0, self.header.answerCount):
            answer = DNSResponse(buf,'Answer')
            self.answers.append(answer)
            self.str_answers.append(str(answer))

        self.authority = []
        self.str_authority = []
        for i in range(0, self.header.authorityCount):
            authorityRecord = DNSResponse(buf,'Authority')
            self.authority.append(authorityRecord)
            self.str_authority.append(str(authorityRecord))

        self.records = []
        self.str_records = []
        for i in range(0, self.header.additionalRecordCount):
            additionalRecord = DNSResponse(buf,'Additional Record')
            self.records.append(additionalRecord)
            self.str_records.append(str(additionalRecord))

    def parse(self, buf):
        # first 12 bytes are DNS packet header
        self.header = DNSHeader(buf)
        # DNS body starts after DNS packet header
        self.parseBody(buf)

    def __str__(self):
        return '''
DNS Packet[
%s
    Questions[
%s
    ],
    Answers[
%s
    ],
    Domain Authority[
%s
    ],
    Additional Information[
%s
    ]
]
            ''' % (self.header, str.join(',\n',self.str_questions), 
                    str.join(',\n',self.str_answers), str.join(',\n',self.str_authority),
                    str.join(',\n',self.str_records))

class DNSHeader:
    def __init__(self, buf):
        self.parse(buf)

    def parse(self, buf):
        header = buf.unpack('!HHHHHH')
        self.id = header[0]
        self.qr = ((header[1] >> 15) == 1)
        self.opcode = (header[1] & 0x7800) >> 11
        self.aa = ((header[1] & 0x400) >> 10 == 1)
        self.tc = ((header[1] & 0x200) >> 9 == 1)
        self.rd = ((header[1] & 0x100) >> 8 == 1)
        self.ra = ((header[1] & 0x80) >> 7 == 1)
        self.rcode = (header[1] & 0xF)
        self.questionCount = header[2]
        self.answerCount = header[3]
        self.authorityCount = header[4]
        self.additionalRecordCount = header[5]

    def __str__(self):
        return '''     Header[
        ID: %i
        Query Response: %s
        Operation Code: %i
        Authoritative Answer Flag: %s
        Truncation Flag: %s
        Recursion Desired: %s
        Recursion Available: %s
        Response Code: %i
        Question Count: %i
        Answer Count: %i
        Authority Count: %i
        Additional Record Count: %i
    ],''' % (self.id, self.qr, self.opcode, self.aa,
            self.tc, self.rd, self.ra, self.rcode,
            self.questionCount, self.answerCount, 
            self.authorityCount, self.additionalRecordCount)

class DNSQuestion:
    def __init__(self, buf):
        self.parse(buf)

    def parse(self, buf):
        self.name = DNSResponse.getName(buf)
        self.qtype = DNSPacket.types[buf.unpack("!H")[0]]
        self.qclass = buf.unpack("!H")[0]

    def __str__(self):
        return '''        Question[
            Name: %s
            Type: %s
            Class: %s
        ]''' % (self.name, self.qtype, self.qclass)

class DNSResponse:
    def __init__(self, buf, title):
        self.title = title
        self.parse(buf)

    def parse(self, buf):
        self.name = DNSResponse.getName(buf)
        typeByte = buf.unpack("!H")[0]
        if typeByte in DNSPacket.types:
            self.qtype = DNSPacket.types[typeByte]
        else:
            self.qtype = "Unknown"
        self.qclass = buf.unpack("!H")[0]
        self.ttl = buf.unpack("!L")[0]
        self.rdlength = buf.unpack("!H")[0]
        self.rdata = ''
        # Parse RData of this QType    
        method_name = 'parseType' + str(self.qtype)
        if method_name in dir(self):
            method = getattr(self, method_name, lambda: "nothing")
            method(buf)
        else:
            # skip RData bytes
            buf.skip(self.rdlength+1)

    @staticmethod
    def getName(buf):
        length = 0
        name = ''
        while True:
            byte = buf.unpack("!B", False)[0]
            pointer = ((byte & 0xC0) >> 6) == 3
            if pointer:
                byte = buf.unpack("!H")[0]
                pointerIndex = (byte & 0x3FFF)
                clone = buf.clone(True)
                clone.point(pointerIndex)
                if name != '':
                    name += '.'
                name += DNSResponse.getName(clone)
                break
            else:
                byte = buf.unpack("!B")[0]
                # end of full name reached
                if byte == 0:
                    break
                # end of label reached
                if length == 0:
                    length = byte
                    if name != '':
                        name += '.'
                # parsing a label
                else:
                    length -= 1
                    name += chr(byte)
        return name

    def parseTypeA(self, buf):
        addr = []
        for i in range(0, self.rdlength):
            byte = buf.unpack("!B")[0]
            addr.append(str(byte))
        self.rdata = 'Addr: ' + str.join('.',addr)

    def parseTypeNS(self, buf):
        self.rdata = 'Name Server: ' + DNSResponse.getName(buf)

    def parseTypeCNAME(self, buf):
        self.rdata = 'Primary Name: ' + DNSResponse.getName(buf)

    def parseTypeSOA(self, buf):
        self.rdata = '''
                Primary Name Server: %s
                Responsible Authority\'s Mailbox: %s
                Serial Number: %i
                Refresh Interval: %i
                Retry Interval: %i
                Expire Limit: %i
                Minimum TTL: %i                
            ''' % (DNSResponse.getName(buf), DNSResponse.getName(buf), 
                    buf.unpack("!L")[0], buf.unpack("!L")[0], buf.unpack("!L")[0], 
                    buf.unpack("!L")[0], buf.unpack("!L")[0])

    def parseTypePTR(self, buf):
        self.rdata = 'Domain Name Pointer: ' + DNSResponse.getName(buf)

    def parseTypeMX(self, buf):
        self.rdata = 'Preference: %i, Exchange Host: %s' % (buf.unpack("!H")[0], DNSResponse.getName(buf))

    def parseTypeTXT(self, buf):
        for i in range(0, self.rdlength):
            self.rdata += chr(buf.unpack("!B")[0])

    def __str__(self):
        return '''        %s[
            Name: %s
            Type: %s
            Class: %s
            TTL: %i
            RData: [%s]
        ]''' % (self.title, self.name, self.qtype, self.qclass, self.ttl, self.rdata)
