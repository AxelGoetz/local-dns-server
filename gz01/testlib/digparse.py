import re

cnamere = re.compile(r'((?:[^ \t\n\r\f\v\.]+\.)+)\s+\d+\s+IN\s+CNAME\s+((?:[^ \t\n\r\f\v\.]+\.)+)')
addressre = re.compile(r'((?:[^ \t\n\r\f\v\.]+\.)+)\s+\d+\s+IN\s+A\s+((?:\d+\.)+\d+)')
nsre = re.compile(r'((?:[^ \t\n\r\f\v\.]+\.)+)\s+\d+\s+IN\s+NS\s+((?:[^ \t\n\r\f\v\.]+\.)+)')

def query_timedout(digout):
  m = re.search(r'connection timed out', digout)
  if m is None:
    return False
  return True

def parse_digout(digout):
  preheader,headertag,postheader = digout.partition('->>HEADER<<-')
  header,question,postquestion = postheader.partition(';; QUESTION SECTION:')
  #print "header =", header
  questionsection,answertag,postanswer = postquestion.partition(';; ANSWER SECTION:')
  #print "questionsection=", questionsection
  answersection,authoritytag,postauthority = postanswer.partition(';; AUTHORITY SECTION:')
  #print "answersection=", answersection
  authoritysection,additionaltag,postadditional = postauthority.partition(';; ADDITIONAL SECTION:')
  #print "authoritysection=", authoritysection
  additionalsection,beginmetadatatag,metadata = postadditional.partition(";;")
  #print "additionalsection=", additionalsection
  #print "metadata=", metadata
  cnames = cnamere.findall(answersection)
  addresses = addressre.findall(answersection)
  authnses = nsre.findall(authoritysection)
  glueaddrs = addressre.findall(additionalsection)

  # convert all names to lower case in the following to avoid DNS
  # server capitalization (as MIT is fond of doing) from corrupting
  # test results.
  address_dict = dict([(a1.lower(), [ ip2 for a2,ip2 in addresses if a1.lower() == a2.lower()]) for (a1,ip1) in addresses])
  cname_dict = dict([(a1.lower(), [ cn2.lower() for a2,cn2 in cnames if a1.lower() == a2.lower()]) for (a1,cn1) in cnames])
  authns_dict = dict([(a1.lower(), [ ns2.lower() for a2,ns2 in authnses if a1.lower() == a2.lower()]) for (a1,ns1) in authnses])
  glueaddr_dict = dict([(a1.lower(), [ ip2 for a2,ip2 in glueaddrs if a1.lower() == a2.lower()]) for (a1,ip1) in glueaddrs])

  return (address_dict, cname_dict, authns_dict, glueaddr_dict)

