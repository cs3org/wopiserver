'''
discovery.py

Helper code for the WOPI discovery phase, as well as
for integrating the apps supported by the bridge functionality.
This code is going to be deprecated once the new Reva AppProvider is fully functional.
'''

from xml.etree import ElementTree as ET
import http.client
import json
import requests
import flask
import bridge

# convenience references to global entities
srv = None
log = None

def registerapp(appname, appurl, appinturl, apikey=None):
    '''Registers the given app in the internal endpoints list'''
    '''For the time being, this is highly customized to keep backwards-compatibility. To be reviewed'''
    if not appinturl:
        appinturl = appurl
    try:
        discReq = requests.get(appurl + '/hosting/discovery', verify=False)
    except requests.exceptions.ConnectionError as e:
        log.error('msg="iopRegisterApp: failed to probe application" appurl="%s" response="%s"' % (appurl, e))
        return 'Error connecting to the provided app URL', http.client.NOT_FOUND

    if discReq.status_code == http.client.OK:
        discXml = ET.fromstring(discReq.content)
        # extract urlsrc from first <app> node inside <net-zone>
        urlsrc = discXml.find('net-zone/app')[0].attrib['urlsrc']
        if urlsrc.find('loleaflet') > 0:
            # this is Collabora
            codetypes = srv.config.get('general', 'codeofficetypes', fallback='.odt .ods .odp').split()
            for t in codetypes:
                srv.endpoints[t] = {}
                srv.endpoints[t]['view'] = urlsrc + 'permission=readonly'
                srv.endpoints[t]['edit'] = urlsrc + 'permission=edit'
                srv.endpoints[t]['new']  = urlsrc + 'permission=edit'        # pylint: disable=bad-whitespace
            log.info('msg="Collabora Online endpoints successfully configured" count="%d" CODEURL="%s"' %
                     (len(codetypes), srv.endpoints['.odt']['edit']))
            return

        # else this must be Microsoft Office Online
        srv.endpoints['.docx'] = {}
        srv.endpoints['.docx']['view'] = appurl + '/wv/wordviewerframe.aspx?edit=0'
        srv.endpoints['.docx']['edit'] = appurl + '/we/wordeditorframe.aspx?edit=1'
        srv.endpoints['.docx']['new']  = appurl + '/we/wordeditorframe.aspx?new=1'                         # pylint: disable=bad-whitespace
        srv.endpoints['.xlsx'] = {}
        srv.endpoints['.xlsx']['view'] = appurl + '/x/_layouts/xlviewerinternal.aspx?edit=0'
        srv.endpoints['.xlsx']['edit'] = appurl + '/x/_layouts/xlviewerinternal.aspx?edit=1'
        srv.endpoints['.xlsx']['new']  = appurl + '/x/_layouts/xlviewerinternal.aspx?edit=1&new=1'         # pylint: disable=bad-whitespace
        srv.endpoints['.pptx'] = {}
        srv.endpoints['.pptx']['view'] = appurl + '/p/PowerPointFrame.aspx?PowerPointView=ReadingView'
        srv.endpoints['.pptx']['edit'] = appurl + '/p/PowerPointFrame.aspx?PowerPointView=EditView'
        srv.endpoints['.pptx']['new']  = appurl + '/p/PowerPointFrame.aspx?PowerPointView=EditView&New=1'  # pylint: disable=bad-whitespace
        log.info('msg="Microsoft Office Online endpoints successfully configured" OfficeURL="%s"' %
                 srv.endpoints['.docx']['edit'])
        return

    elif discReq.status_code == http.client.NOT_FOUND:
        # try and scrape the app homepage to see if a bridge-supported app is found
        try:
            discReq = requests.get(appurl, verify=False).content.decode()
            if discReq.find('CodiMD') > 0:
                bridge.WB.loadplugin(appname, appurl, appinturl, apikey)
                bridgeurl = srv.config.get('general', 'wopiurl') + '/wopi/bridge/open'
                srv.endpoints['.md'] = {}
                srv.endpoints['.md']['view'] = srv.endpoints['.md']['edit'] = bridgeurl
                srv.endpoints['.zmd'] = {}
                srv.endpoints['.zmd']['view'] = srv.endpoints['.zmd']['edit'] = bridgeurl
                srv.endpoints['.txt'] = {}
                srv.endpoints['.txt']['view'] = srv.endpoints['.txt']['edit'] = bridgeurl
                log.info('msg="iopRegisterApp: CodiMD endpoints successfully configured" BridgeURL="%s"' % bridgeurl)
                return

            if discReq.find('Etherpad') > 0:
                bridge.WB.loadplugin(appname, appurl, appinturl, apikey)
                bridgeurl = srv.config.get('general', 'wopiurl') + '/wopi/bridge/open'
                srv.endpoints['.epd'] = {}
                srv.endpoints['.epd']['view'] = srv.endpoints['.epd']['edit'] = bridgeurl
                log.info('msg="iopRegisterApp: Etherpad endpoints successfully configured" BridgeURL="%s"' % bridgeurl)
                return
        except ValueError:
            # bridge plugin could not be initialized
            pass
        except requests.exceptions.ConnectionError:
            pass

    # in all other cases, fail
    log.error('msg="iopRegisterApp: app is not WOPI-compatible" appurl="%s"' % appurl)


def initappsregistry():
    '''Initializes the CERNBox Office-like Apps Registry'''
    # TODO to be deprecated in favour of a /wopi/iop/registerapp endpoint
    oos = srv.config.get('general', 'oosurl', fallback=None)
    if oos:
        registerapp('MSOffice', oos, oos)
    code = srv.config.get('general', 'codeurl', fallback=None)
    if code:
        registerapp('Collabora', code, code)
    codimd = srv.config.get('general', 'codimdurl', fallback=None)
    codimdint = srv.config.get('general', 'codimdinturl', fallback=None)
    if codimd:
        with open('/var/run/secrets/codimd_apikey') as f:
            apikey = f.readline().strip('\n')
            registerapp('CodiMD', codimd, codimdint, apikey)

