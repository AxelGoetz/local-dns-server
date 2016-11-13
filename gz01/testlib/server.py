from gz01.testlib.ServerThread import *

import signal, sys, re, time
from select import select
from subprocess import *

DIGBIN = "/usr/bin/dig"
PYTHONBIN = "./python-wrapper"
STRACEBIN = "/usr/bin/strace"
SERVERSTDOUT = "ncsdns.stdout"
SERVERSTDERR = "ncsdns.stderr"

# Regular expressions to grep strace and dig output.
sendtore = re.compile(r'sendto\(.*?inet_addr\("(\d+\.\d+\.\d+\.\d+)"\)')
recvfromre = re.compile(r'recvfrom\(.*?inet_addr\("(\d+\.\d+\.\d+\.\d+)"\)')

def run_server(serverpath):
  """ 
  Start the server python script given by pathname serverpath, and
  return a tuple (server, serveroutput, serverport).  server is a
  Popen object, serveroutput is the server's stderr output stream, and
  serverport is an integer indicating which port the server is
  listening on for incoming requests.

  """
  # Run the server and wait at most one second for a string telling us
  # which ephemeral port the server is listening on:
  servercmd = (PYTHONBIN, serverpath)
  so = open(SERVERSTDOUT, "w")
  se = open(SERVERSTDERR, "w")
  server = Popen(servercmd, stdout=PIPE, stderr=se, shell=False)
  rds,wds,xds = select([server.stdout], [], [server.stdout], 1.0)
  if (rds,wds,xds) == ([],[],[]):
    print "FAIL: timeout--failed to print assigned port within one second"
    sys.exit(1)
  listenstatement = server.stdout.readline()
  m = re.search(r'listening on port (\d+)$', listenstatement)
  if m is None:
    print "FAIL: failed to print assigned port"
    sys.exit(2)
  st = ServerThread(server.stdout, so)
  st.start()
  serverport = int(m.group(1))
  print "server is listening on port %d" % (serverport,)
  return (server, st, so, se, serverport)


def kill_server(server, serverthread):
  """
  Given a server Popen object previously returned by run_server, kill
  the server and wait for it to terminate.

  """
  print "kill server with SIGINT"
  os.kill(server.pid, signal.SIGINT)
  time.sleep(1)
  if not server.returncode is None:
    print "kill server with SIGKILL"
    os.kill(strace.pid, signal.SIGKILL)
  server.kill()
  #print "join serverthread"
  #serverthread.join()
  server.wait()

def start_strace(server):
  """
  Given a server Popen object previously returned by run_server,
  strace the server, returning the resulting strace Popen object.
  
  """
  stracecmd = (STRACEBIN, "-f", "-etrace=sendto,recvfrom", "-p%d" % (server.pid,))
  strace = Popen(stracecmd, stderr=PIPE, shell=False)
  return strace

def kill_strace(strace):
  """
  Given an strace Popen object previously return by start_strace,
  detach and kill strace, returning a tuple (sendaddrs, recvaddrs)
  indicating the IPs the straced server sent to and received from,
  respectively.

  """
  os.kill(strace.pid, signal.SIGINT)
  time.sleep(1)
  os.kill(strace.pid, signal.SIGKILL)
  straceerr = strace.communicate()[1]
  sendaddrs = set(sendtore.findall(straceerr))
  recvaddrs = set(recvfromre.findall(straceerr))
  return (sendaddrs, recvaddrs)

def dig_query(baselineserver, serverport, thehostname):
  """
  Given the server port returned by start_server, make a query for the
  given DNS hostname to that server port.

  """
  baselinedigcmd = (DIGBIN, "@%s" % (baselineserver,), thehostname)
  baselinedig = Popen(baselinedigcmd, stdout=PIPE, shell=False)
  baselinedigout = baselinedig.communicate()[0]

  testdigcmd = (DIGBIN, "@127.0.0.1", "-p%d" % (serverport,), thehostname)
  testdig = Popen(testdigcmd, stdout=PIPE, shell=False)
  testdigout = testdig.communicate()[0]

  return (baselinedigout, testdigout)

