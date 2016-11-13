"""
Representation of a question section entry in a DNS pocket.
"""

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

from copy import copy
from gz01.inetlib.types import DomainName
import struct

class QE:
  """
  Representation of a question section entry (QE) in a DNS pocket.
  Assumes CLASS_IN (the Internet class).

  Member variables:
  _type -- A 16-bit type distinguishing what question this QE entry is
  asking.  Possible values: { QE.TYPE_A (address query), QE.TYPE_NS
  (NS query), QE.TYPE_CNAME (CNAME query), QE.TYPE_SOA (start of
  authority query), QE.TYPE_PTR (DNS PTR query), QE.TYPE_MX (mail
  exchange query) }.
  """
  
  # values of the _type field
  TYPE_A = 1
  TYPE_NS = 2
  TYPE_CNAME = 5
  TYPE_SOA = 6
  TYPE_PTR = 12
  TYPE_MX = 15

  CLASS_IN = 1

  def __init__(self, type = TYPE_A, dn = None):
    """ Initialize a QE from a user-supplied type and DomainName (see
    gz01.inetlib.DomainName) """
    self._type = type
    self._dn = dn

  def pack(self):
    """ Return a binary-packed string rep. """
    l = [self._dn.pack(), struct.pack(">2H", self._type, QE.CLASS_IN)]
    return "".join(l)

  def __copy__(self):
    """ Return a copy of this QE, recursively copying its members. """
    res = QE(self._type, copy(self._dn))
    return res

  def __str__(self):
    if self._type == QE.TYPE_A:
      return "%-30s\tIN\tA" % (str(self._dn),)
    elif self._type == QE.TYPE_NS:
      return "%-30s\tIN\tNS" % (str(self._dn),)
    elif self._type == QE.TYPE_CNAME:
      return "%-30s\tIN\tCNAME" % (str(self._dn),)
    else:
      return "NIMPL"

  def __len__(self):
    # returns the length of the RFC 1035-compliant packed rep
    return len(self._dn.pack()) + 4

  @staticmethod
  def fromData(data, offset = 0):
    """
    Given packed binary data and an optional offset into that data,
    returns a QE object representing the data.
    """
    qe = QE()
    qe._dn = DomainName.fromData(data, offset)
    (qe._type, qe._class,) = \
          struct.unpack_from(">2H", data, offset + len(qe._dn))
    return qe
