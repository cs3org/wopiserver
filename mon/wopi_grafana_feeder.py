#!/usr/bin/python
'''
wopi_grafana_feeder.py

A daemon pushing CERNBox WOPI monitoring data to Grafana.
TODO: make it a collectd plugin. References:
https://collectd.org/documentation/manpages/collectd-python.5.shtml
https://blog.dbrgn.ch/2017/3/10/write-a-collectd-python-plugin/
https://github.com/dbrgn/collectd-python-plugins

author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''

import fileinput
import socket
import time
import pickle
import struct
import datetime
import getopt
import sys

CARBON_TCPPORT = 2004
carbonHost = ''
verbose = False
prefix = 'cernbox.wopi'
epoch = datetime.datetime(1970, 1, 1)


def usage(exitCode):
  '''prints usage'''
  print 'Usage : cat <logfile> | ' + sys.argv[0] + ' [-h|--help] -g|--grafanahost <hostname>'
  sys.exit(exitCode)

def send_metric(data):
  '''send data to grafana using the pickle protocol'''
  payload = pickle.dumps(data, protocol=2)
  header = struct.pack("!L", len(payload))
  message = header + payload
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((carbonHost, CARBON_TCPPORT))
  sock.sendall(message)
  sock.close()

def get_wopi_metrics(data):
  '''Parse WOPI usage metrics'''
  for line in data:
    if data.isfirstline():
      logdate = line.split('T')[0].split('-')    # keeps the date until 'T', splits
      timestamp = (datetime.datetime(int(logdate[0]), int(logdate[1]), int(logdate[2])) - epoch).total_seconds() + time.altzone
      errors = 0
      users = {}
      openfiles = {}
      openfiles['docx'] = {}
      openfiles['xlsx'] = {}
      openfiles['pptx'] = {}
      openfiles['one'] = {}
      wrfiles = {}
      wrfiles['docx'] = {}
      wrfiles['xlsx'] = {}
      wrfiles['pptx'] = {}
      wrfiles['one'] = {}
      collab = 0
    try:
      if ' ERROR ' in line:
        errors += 1
      # all opened files
      elif 'CheckFileInfo' in line:
        # count of unique users
        l = line.split()
        u = l[4].split('=')[1]
        if u in users.keys():
          users[u] += 1
        else:
          users[u] = 1
        # count of open files per type: look for the file extension
        fname = line[line.find('filename=')+10:line.rfind('fileid=')-2]
        fext = fname[fname.rfind('.')+1:]
        if fext not in openfiles:
          openfiles[fext] = {}
        if fname in openfiles[fext]:
          openfiles[fext][fname] += 1
        else:
          openfiles[fext][fname] = 1
      # files opened for write
      elif 'successfully written' in line:
        # count of written files
        fname = line[line.find('filename=')+10:line.rfind('token=')-2]
        fext = fname[fname.rfind('.')+1:]
        if fname in wrfiles[fext]:
          wrfiles[fext][fname] += 1
        else:
          wrfiles[fext][fname] = 1
      # collaborative editing sessions
      elif 'Collaborative editing detected' in line:
        collab += 1
        # we could extract the filename and the users list for further statistics
    except Exception:
      if verbose:
        print 'Error occurred at line: %s' % line
      raise

  if 'timestamp' not in locals():
    # the file was empty, nothing to do
    return
  # prepare data for grafana
  output = []
  output.append(( prefix + '.errors', (int(timestamp), errors) ))
  output.append(( prefix + '.users', (int(timestamp), len(users)) ))
  # get the top user by sorting the users dict by values instead of by keys
  if len(users) > 0:
    top = sorted(users.iteritems(), key=lambda (k, v): (v, k))[-1][1]
    output.append(( prefix + '.topuser', (int(timestamp), int(top)) ))
  for fext in openfiles:
    output.append(( prefix + '.openfiles.' + fext, (int(timestamp), len(openfiles[fext])) ))
  for fext in wrfiles:
    output.append(( prefix + '.writtenfiles.' + fext, (int(timestamp), len(wrfiles[fext])) ))
  output.append(( prefix + '.collab', (int(timestamp), collab) ))
  # send and print all collected data
  send_metric(output)
  if verbose:
    print output


# first parse options
try:
  options, args = getopt.getopt(sys.argv[1:], 'hvg:', ['help', 'verbose', 'grafanahost'])
except Exception, e:
  print e
  usage(1)
for f, v in options:
  if f == '-h' or f == '--help':
    usage(0)
  elif f == '-v' or f == '--verbose':
    verbose = True
  elif f == '-g' or f == '--grafanahost':
    carbonHost = v
  else:
    print "unknown option : " + f
    usage(1)
if carbonHost == '':
  print 'grafanahost option is mandatory'
  usage(1)
# now parse input and collect statistics
try:
  get_wopi_metrics(fileinput.input('-'))
except Exception, e:
  print 'Error with collecting metrics:', e
  if verbose:
    raise
