# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from ryu.lib import addrconv


class TypeDescr(object):
    pass


class IntDescr(TypeDescr):
    def __init__(self, size):
        self.size = size

    def to_user(self, bin):
        i = 0
        for x in xrange(self.size):
            c = bin[:1]
            i = i * 256 + ord(c)
            bin = bin[1:]
        return i

    def from_user(self, i):
        bin = ''
        for x in xrange(self.size):
            bin = chr(i & 255) + bin
            i /= 256
        return bin

Int1 = IntDescr(1)
Int2 = IntDescr(2)
Int3 = IntDescr(3)
Int4 = IntDescr(4)
Int8 = IntDescr(8)


class MacAddr(TypeDescr):
    size = 6
    to_user = addrconv.mac.bin_to_text
    from_user = addrconv.mac.text_to_bin


class IPv4Addr(TypeDescr):
    size = 4
    to_user = addrconv.ipv4.bin_to_text
    from_user = addrconv.ipv4.text_to_bin


class IPv6Addr(TypeDescr):
    size = 16
    to_user = addrconv.ipv6.bin_to_text
    from_user = addrconv.ipv6.text_to_bin

class BPFMatch(object):
    def __init__(self, prog_num, prog_res, prog_mask, param):
        self.prog_num = prog_num
        self.prog_res = prog_res
        self.prog_mask = prog_mask
	self.param = param

    def __repr__(self):
        return "prognum:" + hex(self.prog_num) + ", prog_res:" + hex(self.prog_res) + ", prog_mask:" + hex(self.prog_mask) + ", parameter: " + self.param.encode("hex")


class BPFProgram(object):
    def __init__(self, instructions):
        self.instructions = instructions

import struct
class Filter(TypeDescr):
    size = 248

    @staticmethod
    def to_user(bin):
        program = BPFProgram([])
        for x in range(Filter.size/8):
            program.instructions.append(struct.unpack_from('HBBI', bin, offset=x*8))
        return program

    @staticmethod
    def from_user(i):
        bin = ''.join([struct.pack('HBBI', *v) for v in i.instructions])
        padding = chr(0) * (Filter.size-len(bin))
        return bin + padding


class ExecBpf(TypeDescr):
    size = 248

    @staticmethod
    def to_user(bin):
        prognum, progres, progmask, paramlen = struct.unpack('!IQQB', bin[:21])
        param, = struct.unpack("%ds" % paramlen, bin[21:21+paramlen])
        return BPFMatch(prognum, progres, progmask, param)
    
    @staticmethod
    def from_user(i):
        bin = struct.pack('!IQQB%ds' % len(i.param) ,i.prog_num, i.prog_res, i.prog_mask, len(i.param), i.param)
	print 'Size: ' + str(len(bin))
	padding = chr(0) * (Filter.size-len(bin))
        return bin + padding

class UnknownType(TypeDescr):
    import base64

    to_user = staticmethod(base64.b64encode)
    from_user = staticmethod(base64.b64decode)
