'''
wsgi.py

A tiny wrapper to run wopiserver.py inside wsgi and Nginx

Author: Giuseppe.LoPresti@cern.ch
CERN/IT-ST
'''
from wopiserver import Wopi

Wopi.init()
Wopi.log.info('msg="WOPI Server starting in Nginx mode"')
Wopi.useHttps = False    # force http as SSL is handled by nginx
application = Wopi.app        # from now on control is given to uwsgi
