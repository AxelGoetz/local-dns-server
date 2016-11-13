# Copyright (C) 2009 Kyle Jamieson

""" Utility functions for gz01. """

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

import logging, logging.handlers
import signal, sys

DEBUG1 = 9
DEBUG2 = 8
logfile = "./ncsdns.log"

logging.addLevelName(DEBUG1, "DEBUG1")
logging.addLevelName(DEBUG2, "DEBUG2")

logger = logging.getLogger()
logger.setLevel(DEBUG2) # do not alter

# Create console handler and set level.  You may configure the
# following call to ch.setLevel in order to alter the verbosity of
# messages output to the console.
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
chformatter = logging.Formatter("%(levelname)-7s: %(message)s")
ch.setFormatter(chformatter)

# Create file handler and set verbosity level.  You may configure the
# following call to fh.setLevel in order to alter the verbosity of
# messages output to the log file.
fh = logging.handlers.RotatingFileHandler(logfile, 'a', 2000000, 5)
fh.setLevel(DEBUG2)
fhformatter = logging.Formatter("%(message)s")
fh.setFormatter(fhformatter)

logger.addHandler(ch)
logger.addHandler(fh)

def signal_handler(signal, frame):
  fh.doRollover()
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def hexdump(src, length=16):
  """ 
  Dump combined hex/ascii rep of a packed binary string to stdout.

  [Credit: code.activestate.com] 

  src -- packed binary data to hex dump.
  length -- number of octets per line to display.
  """
  result=[]
  for i in xrange(0, len(src), length):
    s = src[i:i+length]
    hexa = ' '.join(["%02X"%ord(x) for x in s])
    printable = s.translate(FILTER)
    result.append("%04X   %-*s   %s\n" % (i, length*3, hexa, printable))
  return ''.join(result)

