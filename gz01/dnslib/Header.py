""" Representation of the DNS protocol header"""

# Copyright (C) 2009 Kyle Jamieson

# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct

class Header:
  """
  Representation of the DNS protocol header.

  Member variables:

  _id -- the 16-bit DNS query identifier.

  _opcode -- the 4-bit DNS query opcode, one of {
    Header.OPCODE_QUERY, Header.OPCODE_IQUERY, Header.OPCODE_STATUS
    }.

  _rcode -- the 4-bit DNS response code, one of { Header.RCODE_NOERR,
    Header.RCODE_FORMATERR, Header.RCODE_SERVFAIL,
    Header.RCODE_NAMEERR, Header.RCODE_NIMPL }.

  _qdcount -- number of question entries indicated in the Header

  _ancount -- number of answer entries indicated in the Header

  _nscount -- number of authoritative entries indicated in the Header

  _arcount -- number of additional entries indicated in the Header

  _qr -- A one bit field that specifies whether this message is a
        query (0), or a response (1).
  _aa -- Authoritative Answer - this bit is valid in responses, and
        specifies that the responding name server is an authority
        for the domain name in question section.
  _tc -- TrunCation - specifies that this message was truncated due
        to length greater than that permitted on the transmission
        channel.
  _rd -- Recursion Desired - this bit may be set in a query and is
        copied into the response.  If RD is set, it directs the name
        server to pursue the query recursively.  Recursive query
        support is optional.
  _ra -- Recursion Available - this be is set or cleared in a
        response, and denotes whether recursive query support is
        available in the name server.
  """

  QUERY = 0
  RESPONSE = 1

  RCODE_NOERR = 0
  RCODE_FORMATERR = 1
  RCODE_SRVFAIL = 2
  RCODE_NAMEERR = 3
  RCODE_NIMPL = 4

  OPCODE_QUERY = 0
  OPCODE_IQUERY = 1
  OPCODE_STATUS = 2

  # flag field bit offsets, network order
  OFFSET_QR = 15
  OFFSET_OPCODE = 11
  OFFSET_AA = 10
  OFFSET_TC = 9
  OFFSET_RD = 8
  OFFSET_RA = 7
  OFFSET_Z = 6
  OFFSET_RCODE = 0

  def __init__(self, id, opcode, rcode, qdcount=0, ancount=0, nscount=0,
               arcount=0, qr=False, aa=False, tc=False, rd=False,
               ra=False):
    """
    Initialize the Header from supplied arguments.

    id -- the 16-bit DNS query identifier of the query

    opcode -- the 4-bit DNS query opcode, one of {
      Header.OPCODE_QUERY, Header.OPCODE_IQUERY, Header.OPCODE_STATUS
      }.

    rcode -- the 4-bit DNS response code, one of { Header.RCODE_NOERR,
      Header.RCODE_FORMATERR, Header.RCODE_SERVFAIL,
      Header.RCODE_NAMEERR, Header.RCODE_NIMPL }.

    Keyword arguments:
    qdcount -- number of question entries indicated in the Header
    ancount -- number of answer entries indicated in the Header
    nscount -- number of authoritative entries indicated in the Header
    arcount -- number of additional entries indicated in the Header
    qr -- A one bit field that specifies whether this message is a
          query (0), or a response (1).
    aa -- Authoritative Answer - this bit is valid in responses, and
          specifies that the responding name server is an authority
          for the domain name in question section.
    tc -- TrunCation - specifies that this message was truncated due
          to length greater than that permitted on the transmission
          channel.
    rd -- Recursion Desired - this bit may be set in a query and is
          copied into the response.  If RD is set, it directs the name
          server to pursue the query recursively.  Recursive query
          support is optional.
    ra -- Recursion Available - this be is set or cleared in a
          response, and denotes whether recursive query support is
          available in the name server.
    """
    self._id = id
    self._rcode = rcode
    self._opcode = opcode

    self._qdcount = qdcount
    self._ancount = ancount
    self._nscount = nscount
    self._arcount = arcount

    self._qr = qr
    self._aa = aa
    self._tc = tc
    self._rd = rd
    self._ra = ra

  @staticmethod
  def fromData(headerdata, offset = 0):
    """Return a new Header object from the supplied binary data."""
    (id, flags, qdc, anc, nsc, arc,) = \
          struct.unpack_from(">6H", headerdata, offset)
    qr_ = (flags >> Header.OFFSET_QR) & 0x1
    aa_ = (flags >> Header.OFFSET_AA) & 0x1
    tc_ = (flags >> Header.OFFSET_TC) & 0x1
    rd_ = (flags >> Header.OFFSET_RD) & 0x1
    ra_ = (flags >> Header.OFFSET_RA) & 0x1
    opcode = (flags >> Header.OFFSET_OPCODE) & 0xF
    rcode = (flags >> Header.OFFSET_RCODE) & 0xF
    res = Header(id, opcode, rcode, qdcount=qdc, ancount=anc,
                 nscount=nsc, arcount=arc, qr=qr_, aa=aa_, tc=tc_,
                 rd=rd_, ra=ra_)
    return res

  def __len__(self):
    """
    Return the length of the Header's binary string representation.
    """
    return 12

  def __str__(self):
    """
    Return a human-readable string representation of the Header.
    """
    d = dict()

    if self._opcode == Header.OPCODE_QUERY:
      d['opcode'] = "QUERY"
    elif self._opcode == Header.OPCODE_IQUERY:
      d['opcode'] = "IQUERY"
    elif self._opcode == Header.OPCODE_STATUS:
      d['opcode'] = "STATUS"
    else:
      d['opcode'] = "RESERVED"

    if self._rcode == Header.RCODE_NOERR:
      d['status'] = "NOERROR"
    elif self._rcode == Header.RCODE_FORMATERR:
      d['status'] = "FORMATERR"
    elif self._rcode == Header.RCODE_SRVFAIL:
      d['status'] = "SRVFAIL"
    elif self._rcode == Header.RCODE_NAMEERR:
      d['status'] = "NAMEERR"
    elif self._rcode == Header.RCODE_NIMPL:
      d['status'] = "NIMPL"

    d['id'] = self._id

    fl = []
    if self._qr:
      fl.append('qr')
    if self._aa:
      fl.append('aa')
    if self._tc:
      fl.append('tc')
    if self._rd:
      fl.append('rd')
    if self._ra:
      fl.append('ra')

    if len(fl):
      d['flags'] = ", ".join(fl)
    else:
      d['flags'] = "(none)"

    d['qdcount'] = self._qdcount
    d['ancount'] = self._ancount
    d['nscount'] = self._nscount
    d['arcount'] = self._arcount
    
    return "->>HEADER<<- opcode: %(opcode)s, status: %(status)s, id: %(id)u\n\
    flags: %(flags)s; QUERY: %(qdcount)d, ANSWER: %(ancount)d,\
    AUTHORITY: %(nscount)d, ADDITIONAL: %(arcount)d" % d

  def pack(self):
    """
    Return a packed binary string representation of the Header.
    """
    flags = (1 if self._qr else 0) << self.OFFSET_QR | \
            self._opcode << self.OFFSET_OPCODE | \
            (1 if self._aa else 0) << self.OFFSET_AA | \
            (1 if self._tc else 0) << self.OFFSET_TC | \
            (1 if self._rd else 0) << self.OFFSET_RD | \
            (1 if self._ra else 0) << self.OFFSET_RA | \
            self._rcode << self.OFFSET_RCODE
    l = [ struct.pack(">H", self._id), struct.pack(">H", flags),
          struct.pack(">4H", self._qdcount, self._ancount,
                      self._nscount, self._arcount) ]
    return "".join(l)
