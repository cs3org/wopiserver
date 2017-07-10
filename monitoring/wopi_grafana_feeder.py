#!/usr/bin/python
'''
wopi_grafana_feeder.py

A daemon pushing CERNBox WOPI monitoring data to Grafana.

author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''

import subprocess
import re
import socket
import time
import sys
import pickle
import struct

CARBON_HOST = 'filer-carbon.cern.ch'
CARBON_TCPPORT = 2004
CARBON_UDPPORT = 2003
prefix = 'cernbox.wopi'
logfile = '/var/log/wopi/wopiserver.log'

def send_metric(data):
    payload = pickle.dumps(data, protocol=2)
    header = struct.pack("!L", len(payload))
    message = header + payload
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((CARBON_HOST, CARBON_TCPPORT))
    sock.sendall(message)
    sock.close()

def udp_send_metric(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    carbon_udp = socket.gethostbyname(CARBON_HOST)
    for entry in data:
      msg = entry[0] +' '+ repr(entry[1][1]) +' '+ str(entry[1][0])
      #print msg
      sock.sendto(msg, (carbon_udp, CARBON_UDPPORT))
    sock.close()

# WOPI usage metrics
def get_wopi_metrics():
#  try:
  timestamp = time.time()
  output = []
  # count of unique users
  nbUsers = subprocess.check_output("grep CheckFileIfo %s | awk '{print $5}' |sort|uniq|wc -l" % logfile, shell=True)
  output.append(( prefix + '.users', (int(timestamp), nbUsers) ))
  # count of opened unique files
  nbOpenFiles = subprocess.check_output("grep CheckFileInfo %s | awk '{print $(NF-1)}' |sort|uniq|wc -l" % logfile, shell=True)
  output.append(( prefix + '.openfiles', (int(timestamp), nbOpenFiles) ))
  # count of written files
  nbWrFiles = subprocess.check_output("grep 'successfully written' %s | sed 's/^.*filename/file/' |sort|uniq|wc -l" % logfile, shell=True)
  output.append(( prefix + '.writtenfiles', (int(timestamp), nbWrFiles) ))
  # send all collected data
  send_metric(output)
#  except Exception, e:


if __name__ == '__main__':
  get_wopi_metrics()
