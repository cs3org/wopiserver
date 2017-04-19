'''
wsgi.py

A tiny wrapper to run wopiserver.py inside wsgi and Nginx

Author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''
from wopiserver import Wopi

Wopi.init()
Wopi.useNginx = True
Wopi.log.info('msg="WOPI Server starting in Nginx embedded mode"')
app = Wopi.app

