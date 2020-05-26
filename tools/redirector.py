#!/bin/python
'''
redirector.py

A redirector from http on port 80 to https according to the WOPI server configuration

Author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''

import sys, ConfigParser
import logging
import logging.handlers
try:
  import flask                 # Flask app server, python-flask-0.10.1-4.el7.noarch.rpm + pyOpenSSL-0.13.1-3.el7.x86_64.rpm
except ImportError:
  print "Missing modules, please install python-flask"
  sys.exit(-1)

# Initialization (cf. wopiserver.py)
try:
  _loglevels = {"Critical": logging.CRITICAL,  # 50
                "Error":    logging.ERROR,     # 40
                "Warning":  logging.WARNING,   # 30
                "Info":     logging.INFO,      # 20
                "Debug":    logging.DEBUG      # 10
               }
  # read the configuration
  config = ConfigParser.SafeConfigParser()
  config.readfp(open('/etc/wopi/wopiserver.defaults.conf'))    # fails if the file does not exist
  config.read('/etc/wopi/wopiserver.conf')
  # prepare the Flask web app
  app = flask.Flask("WOPIServer-redirect")
  log = app.logger
  log.setLevel(_loglevels[config.get('general', 'loglevel')])
  loghandler = logging.FileHandler('/var/log/cernbox/wopiserver.log')
  loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                            datefmt='%Y-%m-%dT%H:%M:%S'))
  log.addHandler(loghandler)
  useHttps = config.get('security', 'usehttps').lower() == 'yes'
  if not useHttps:
    print 'WOPI Server configured in plain http, bailing out'
    sys.exit(-1)
except Exception, e:
  # any error we get here with the configuration is fatal
  print "Failed to initialize the service, bailing out:", e
  sys.exit(-1)


@app.before_request
def before_request():
  '''Redirects http to https in case https is used'''
  url = flask.request.url
  log.info('msg="Redirected to https" client="%s"' % flask.request.remote_addr)
  url = url.replace('http://', 'https://', 1)
  return flask.redirect(url, code=301)


app.run(host='0.0.0.0', port=80, threaded=False)
