#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5
DNS_PORT = 53
MAX_RECURSION = 1000
CURRENT_RECURSION = 0

# Tries multiple times to send a packet
MAX_TRY = 3

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)




# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure;
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."),
            OrderedDict([(DomainName(ROOTNS_DN),
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))])

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

def parseSectionList(data, length, offset):
  """
  The answer section and the additional section might contain multiple records
  This method iterates over the data and adds the records to the array
  """
  array = []

  for i in range(length):
    (rr, length) = RR.fromData(data, offset)
    offset += length
    array.append(rr)

  return (array, offset)

def parseDNSPacket(data):
  """
  Extracts useful DNS information from a binary format
  """
  newData = {
    'header': None, 'question': None, 'answers': None, 'authority': None, 'additional': None
  }
  offset = 0

  newData['header'] = Header.fromData(data, offset)
  offset += newData['header'].__len__()
  newData['question'] = QE.fromData(data, offset)
  offset += newData['question'].__len__()

  (newData['answers'], offset) = parseSectionList(data, newData['header']._ancount, offset)
  (newData['authority'], offset) = parseSectionList(data, newData['header']._nscount, offset)
  (newData['additional'], offset) = parseSectionList(data, newData['header']._arcount, offset)

  return newData

def constructDNSQuery(id, question):
  """
  Construct a query (in binary format), given an id and a QE object
  """
  header = Header(id, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1)
  query = header.pack()
  query += question.pack()
  return query

def createDNSReply(id, question, result):
  header = Header(id, Header.OPCODE_QUERY, Header.RCODE_NOERR,
    qdcount=1, ancount=1, nscount=len(result['authority']),
    arcount=len(result['additional']), qr=1)

  query = header.pack()
  query += question.pack()
  query += result['answer'].pack()

  for authority in result['authority']:
    query += authority.pack()

  for additional in result['additional']:
    query += additional.pack()

  return query

def createDNSErrorReply(id, question, rcode):
  header = Header(id, Header.OPCODE_QUERY, rcode, qdcount=1, qr=1)

  query = header.pack()
  query += question.pack()

  return query


def sendQuery(packet, destination):
  """
  Tries `MAX_TRY` amounts to send the packet to the destination
  """
  i = MAX_TRY
  data = {'rcode': Header.RCODE_NOERR}
  address = None
  while i > 0:
    try:
      cs.sendto(packet, (destination, DNS_PORT))
      (data, address) = cs.recvfrom(512)
    except error:
      i -= 1
    else:
      break
  else:
    data['rcode'] = Header.RCODE_SRVFAIL
    logger.error("Could not send data")

  return (data, address)

def addAuthorityToCache(authorities):
  for authority in authorities:
    if authority._type != RR.TYPE_NS:
      continue
    addToNSCache(authority._dn, authority._nsdn, authority._ttl)

def addAdditionalToCache(additionals):
  for additional in additionals:
    if additional._type != RR.TYPE_A:
      continue
    addToACache(additional._dn, inet_ntoa(additional._addr), additional._ttl)


def filterAuthorityRecords(data):
  """
  Since all of the additional records have been tried already,
  it does deletes the matching authority records to avoid
  double checking
  """
  i = 0
  while i < len(data['authority']):
    authority = data['authority'][i]
    for additional in data['additional']:
      if authority._nsdn.__str__() == additional._dn.__str__():
        del data['authority'][i]
        i -= 1
        break
    i += 1


def checkAuthorityRecords(id, question, data, seenCNAME):
  """
  If no additional record is found, check the authority records
  """
  filterAuthorityRecords(data)
  for authority in data['authority']:
    if authority._type != RR.TYPE_NS:
      continue
    newQuestion = QE(dn=authority._nsdn)
    result = recursiveQuery(id, newQuestion, ROOTNS_IN_ADDR, seenCNAME)
    if result['rcode'] == Header.RCODE_NOERR:
      result1 = recursiveQuery(id, question, inet_ntoa(result['answer']._addr), seenCNAME)
      if result1['rcode'] == Header.RCODE_NOERR:
        return result1

    return {'rcode': Heade.RCODE_SRVFAIL}

def checkAdditionalRecords(id, question, data, seenCNAME):
  """
  Checks the glue records that could be used to find the answer
  """
  addAuthorityToCache(data['authority'])
  addAdditionalToCache(data['additional'])

  for additional in data['additional']:
    if additional._type != RR.TYPE_A:
      continue

    addr = inet_ntoa(additional._addr) # Convert from binary
    result = recursiveQuery(id, question, addr, seenCNAME)
    if result is not None and result['rcode'] == Header.RCODE_NOERR:
      if seenCNAME and len(result['authority']) == 0 and len(result['additional']) == 0:
        result['authority'] = filter((lambda x: x._type == RR.TYPE_NS), data['authority'])
        result['additional'] = filter((lambda x: x._type == RR.TYPE_A), data['additional'])
      return result

  return checkAuthorityRecords(id, question, data, seenCNAME)

def queryCNAME(id, question, destination, data):
  addToCNameCache(data._dn, data._cname, data._ttl)
  newQuestion = QE(dn=data._cname)
  result = recursiveQuery(id, newQuestion, ROOTNS_IN_ADDR, True)

  cnameAnswer = result['answer']

  result['answer'] = RR_A(question._dn, cnameAnswer._ttl, cnameAnswer._addr)

  return result

def recursiveQuery(id, question, destination, seenCNAME):
  """
  Performs the iterative query and stores the result in the cache
  Returns None if an error occurred and a dict object otherwise
  """
  global CURRENT_RECURSION
  CURRENT_RECURSION += 1
  if CURRENT_RECURSION == MAX_RECURSION: # To avoid infinite loops
    return {'rcode': Header.RCODE_SRVFAIL}
  packet = constructDNSQuery(id, question)
  (data, address) = sendQuery(packet, destination)
  data = parseDNSPacket(data)

  if data['header']._ancount > 0:
    for answer in data['answers']:
      if answer._type == RR.TYPE_CNAME:
        return queryCNAME(id, question, destination, answer)
      elif answer._type == RR.TYPE_A:
        addToACache(question._dn, inet_ntoa(answer._addr), answer._ttl)
        return {'answer': answer, 'authority': [], 'additional': [], 'rcode': data['header']._rcode}

  elif data['header']._rcode != Header.RCODE_NOERR:
    return {'rcode ': data['header']._rcode}
  else:
    return checkAdditionalRecords(id, question, data, seenCNAME)

def addToACache(dn, ip, ttl):
  value = CacheEntry(expiration=ttl+int(time()), authoritative=True)
  acache[dn] = ACacheEntry(dict([(ip, value)]))

def addToNSCache(dn, dn1, ttl):
    value = CacheEntry(expiration=ttl+int(time()), authoritative=True)
    if dn in nscache:
      nscache[dn][dn1] = value
    else:
      nscache[dn] = dict([(dn1, value)])

def addToCNameCache(dn, dn1, ttl):
  cnamecache[dn] = CnameCacheEntry(dn1, expiration=ttl+int(time()), authoritative=True)

def searchACache(dn):
  """
  Searches if there is a direct answer in the acache
  Returns False if no answer is found
  """
  if dn in acache:
    for ip in acache[dn]._dict.keys():
      if acache[dn]._dict[ip]._expiration < int(time()):
        del acache[dn]._dict[ip]
      else:
        answer = RR_A(dn, acache[dn]._dict[ip]._expiration - int(time()), inet_aton(ip))
        return {'answer': answer, 'authority': [], 'additional': [], 'rcode': Header.RCODE_NOERR}
  return False

def searchCNameCache(dn, addAuthority):
  """
  If no RR_A record is found in the acache, try to find
  a cname and add the appropriate NS and glue records
  @param addAuthority [Boolean value that shows whether it should add the authority]
  """
  if dn in cnamecache:
    if cnamecache[dn]._expiration < int(time()):
      del cnamecache[dn]
    else:
      result = searchCache(cnamecache[dn]._cname)
      if result != False:
        result['answer'] = RR_A(dn, result['answer']._ttl, result['answer']._addr)
        if len(result['additional']) == 0 and len(result['authority']) == 0 and addAuthority:
          result['authority'] = searchNSCache(cnamecache[dn]._cname)
          result['additional'] = findGlueRecords(result['authority'])
      return result

  return False

def searchNSCache(dn):
  """
  Searches the NS cache for the authority records
  Returns a list of RR_NS records
  """
  answer = []
  if dn in nscache:
    for dn1 in nscache[dn].keys():
      if nscache[dn][dn1]._expiration < int(time()):
        del nscache[dn][dn1]
      else:
        answer.append(RR_NS(dn, nscache[dn][dn1]._expiration - int(time()), dn1))

  if len(answer) == 0 and dn.__str__() != ".":
    answer = searchNSCache(dn.parent())

  return answer

def findGlueRecords(authorities):
  """
  Gets a list of RR_NS records and tries to find the
  matching RR_A records.
  """
  answer = []
  for authority in authorities:
    result = searchCache(authority._nsdn, addAuthority=False)
    if result != False:
      answer.append(result['answer'])

  return answer

def searchCache(dn, addAuthority=True):
  """
  Returns a dictionary when an answer is found in cache
  and False otherwise
  """
  result = searchACache(dn)
  if result != False:
    return result
  result = searchCNameCache(dn, addAuthority)
  if result != False:
    return result

  return False

def findResult(id, question):
  result = searchCache(question._dn)
  if result != False:
    return result
  else:
    return recursiveQuery(id, question, ROOTNS_IN_ADDR, False)

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (data, address) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  CURRENT_RECURSION = 0
  if not data:
    logger.error("client provided no data")
  else:
    reply = None
    DNSPacket = parseDNSPacket(data)
    result = findResult(DNSPacket['header']._id, DNSPacket['question'])
    if result is None:
        reply = createDNSErrorReply(DNSPacket['header']._id, DNSPacket['question'], Header.RCODE_SRVFAIL)
    elif result['rcode'] == Header.RCODE_NOERR:
      reply = createDNSReply(DNSPacket['header']._id, DNSPacket['question'], result)
    else:
      reply = createDNSErrorReply(DNSPacket['header']._id, DNSPacket['question'], result['rcode'])
    ss.sendto(reply, address)
