'''
wsgi.py

A tiny wrapper to run wopiserver.py inside wsgi and Nginx

Author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''
from wopiserver import Wopi

Wopi.init()
app = Wopi.app
Wopi.log.info('msg="WOPI Server starting in Nginx mode"')
Wopi.useHttps = False
Wopi.run()
