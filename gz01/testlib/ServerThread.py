import os
from subprocess import *
from threading import Thread

class ServerThread(Thread):
  def __init__(self, serverso, studentso):
    Thread.__init__(self)
    self.serverso = serverso
    self.studentso = studentso

  def run(self):
    while 1:
      bytesread = os.read(self.serverso.fileno(), 1000)
      if bytesread == 0:
        break
      try:
        os.write(self.studentso.fileno(), bytesread)
      except ValueError:
        break
