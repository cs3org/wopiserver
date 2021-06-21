'''
discovery.py

Helper code for the WOPI discovery phase, as well as
for integrating the apps supported by the bridge functionality.
'''

import time
import configparser
import json
import http.client
import requests
from xml.etree import ElementTree as ET
import flask
from urllib.parse import quote_plus as url_quote_plus
from urllib.parse import unquote as url_unquote
import core.wopiutils as utils

# convenience references to global entities
st = None
srv = None
log = None


def registerapp(srv):
    pass


def initappsregistry(srv):
    '''Initializes the CERNBox Office-like Apps Registry'''
    # TODO to be deprecated in favour of a /wopi/iop/registerapp endpoint
    oos = srv.config.get('general', 'oosurl', fallback=None)
    if oos:
        # The supported Microsoft Office Online end-points
        srv.endpoints['.docx'] = {}
        srv.endpoints['.docx']['view'] = oos + '/wv/wordviewerframe.aspx?edit=0'
        srv.endpoints['.docx']['edit'] = oos + '/we/wordeditorframe.aspx?edit=1'
        srv.endpoints['.docx']['new']  = oos + '/we/wordeditorframe.aspx?new=1'                          # pylint: disable=bad-whitespace
        srv.endpoints['.xlsx'] = {}
        srv.endpoints['.xlsx']['view'] = oos + '/x/_layouts/xlviewerinternal.aspx?edit=0'
        srv.endpoints['.xlsx']['edit'] = oos + '/x/_layouts/xlviewerinternal.aspx?edit=1'
        srv.endpoints['.xlsx']['new']  = oos + '/x/_layouts/xlviewerinternal.aspx?edit=1&new=1'          # pylint: disable=bad-whitespace
        srv.endpoints['.pptx'] = {}
        srv.endpoints['.pptx']['view'] = oos + '/p/PowerPointFrame.aspx?PowerPointView=ReadingView'
        srv.endpoints['.pptx']['edit'] = oos + '/p/PowerPointFrame.aspx?PowerPointView=EditView'
        srv.endpoints['.pptx']['new']  = oos + '/p/PowerPointFrame.aspx?PowerPointView=EditView&New=1'   # pylint: disable=bad-whitespace
        log.info('msg="Microsoft Office Online endpoints successfully configured" OfficeURL="%s"' % srv.endpoints['.docx']['edit'])

    code = srv.config.get('general', 'codeurl', fallback=None)
    if code:
        try:
            discData = requests.get(url=(code + '/hosting/discovery'), verify=False).content
            discXml = ET.fromstring(discData)
            # extract urlsrc from first <app> node inside <net-zone>
            urlsrc = discXml.find('net-zone/app')[0].attrib['urlsrc']

            # The supported Collabora end-points: as Collabora supports most Office-like files (including MS Office), we include here
            # only the subset defined in the `codeofficetypes` configuration option, defaulting to just the core ODF types
            codetypes = srv.config.get('general', 'codeofficetypes', fallback='.odt .ods .odp').split()
            for t in codetypes:
                srv.endpoints[t] = {}
                srv.endpoints[t]['view'] = urlsrc + 'permission=readonly'
                srv.endpoints[t]['edit'] = urlsrc + 'permission=edit'
                srv.endpoints[t]['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
            log.info('msg="Collabora Online endpoints successfully configured" count="%d" CODEURL="%s"' %
                            (len(codetypes), srv.endpoints['.odt']['edit']))

        except (IOError, ET.ParseError) as e:
            log.warning('msg="Failed to initialize Collabora Online endpoints" error="%s"' % e)

    # The WOPI Bridge end-point
    bridge = srv.config.get('general', 'wopibridgeurl', fallback=None)
    if not bridge:
        # fallback to the same WOPI url but on default port 8000
        bridge = urllib.parse.urlsplit(srv.wopiurl)
        bridge = '%s://%s:8000/wopib' % (bridge.scheme, bridge.netloc[:bridge.netloc.find(':')+1])
    # The bridge only supports CodiMD for now, therefore this is hardcoded:
    # once we move to the Apps Registry microservice, we can make it dynamic
    srv.endpoints['.md'] = {}
    srv.endpoints['.md']['view'] = srv.endpoints['.md']['edit'] = bridge + '/open'
    srv.endpoints['.zmd'] = {}
    srv.endpoints['.zmd']['view'] = srv.endpoints['.zmd']['edit'] = bridge + '/open'
    srv.endpoints['.txt'] = {}
    srv.endpoints['.txt']['view'] = srv.endpoints['.txt']['edit'] = bridge + '/open'
    srv.endpoints['.epd'] = {}    # Etherpad, for testing
    srv.endpoints['.epd']['view'] = srv.endpoints['.epd']['edit'] = bridge + '/open'
    log.info('msg="WOPI Bridge endpoints successfully configured" BridgeURL="%s"' % bridge)
