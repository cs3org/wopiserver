'''
discovery.py

Helper code for the WOPI discovery phase, as well as for integrating the apps
supported by the bridge functionality.
This code is deprecated and is only used in conjunction with the xroot storage interface:
when the WOPI server is interfaced to Reva via the cs3 storage interface this code is disabled.

Main author: Giuseppe.LoPresti@cern.ch, CERN/IT-ST
'''

from xml.etree import ElementTree as ET
import http.client
import requests
import bridge

# convenience references to global entities
config = None
codetypes = None
log = None

# map of all registered apps' endpoints
endpoints = {}


def registerapp(appname, appurl, appinturl, apikey=None):
    '''Registers the given app in the internal endpoints list
       For the time being, this is highly customized to keep backwards-compatibility. To be reviewed'''
    if not appinturl:
        appinturl = appurl
    try:
        discReq = requests.get(appurl + '/hosting/discovery', verify=False)
    except requests.exceptions.ConnectionError as e:
        log.error('msg="Failed to probe application" appurl="%s" response="%s"' % (appurl, e))
        return

    if discReq.status_code == http.client.OK:
        discXml = ET.fromstring(discReq.content)
        # extract urlsrc from first <app> node inside <net-zone>
        urlsrc = discXml.find('net-zone/app')[0].attrib['urlsrc']
        if urlsrc.find('loleaflet') > 0:
            # this is Collabora
            for t in codetypes:
                endpoints[t] = {}
                endpoints[t]['view'] = urlsrc + 'permission=readonly'
                endpoints[t]['edit'] = urlsrc + 'permission=edit'
                endpoints[t]['new']  = urlsrc + 'permission=edit'   # noqa: E221
            log.info('msg="Collabora Online endpoints successfully configured" count="%d" CODEURL="%s"' %
                     (len(codetypes), endpoints['.odt']['edit']))
            return

        # else this must be Microsoft Office Online
        endpoints['.docx'] = {}
        endpoints['.docx']['view'] = appurl + '/wv/wordviewerframe.aspx?edit=0'
        endpoints['.docx']['edit'] = appurl + '/we/wordeditorframe.aspx?edit=1'
        endpoints['.docx']['new']  = appurl + '/we/wordeditorframe.aspx?new=1'   # noqa: E221
        endpoints['.xlsx'] = {}
        endpoints['.xlsx']['view'] = appurl + '/x/_layouts/xlviewerinternal.aspx?edit=0'
        endpoints['.xlsx']['edit'] = appurl + '/x/_layouts/xlviewerinternal.aspx?edit=1'
        endpoints['.xlsx']['new']  = appurl + '/x/_layouts/xlviewerinternal.aspx?edit=1&new=1'   # noqa: E221
        endpoints['.pptx'] = {}
        endpoints['.pptx']['view'] = appurl + '/p/PowerPointFrame.aspx?PowerPointView=ReadingView'
        endpoints['.pptx']['edit'] = appurl + '/p/PowerPointFrame.aspx?PowerPointView=EditView'
        endpoints['.pptx']['new']  = appurl + '/p/PowerPointFrame.aspx?PowerPointView=EditView&New=1'   # noqa: E221
        log.info('msg="Microsoft Office Online endpoints successfully configured" OfficeURL="%s"' %
                 endpoints['.docx']['edit'])
        return

    if discReq.status_code == http.client.NOT_FOUND:
        # try and scrape the app homepage to see if a bridge-supported app is found
        try:
            discReq = requests.get(appurl, verify=False).content.decode()
            if discReq.find('CodiMD') > 0:
                bridge.WB.loadplugin(appname, appurl, appinturl, apikey)
                endpoints['.md'] = {}
                endpoints['.md']['view'] = endpoints['.md']['edit'] = appurl
                endpoints['.zmd'] = {}
                endpoints['.zmd']['view'] = endpoints['.zmd']['edit'] = appurl
                endpoints['.txt'] = {}
                endpoints['.txt']['view'] = endpoints['.txt']['edit'] = appurl
                log.info('msg="CodiMD endpoints successfully configured" CodiMDURL="%s"' % appurl)
                return

            if discReq.find('Etherpad') > 0:
                bridge.WB.loadplugin(appname, appurl, appinturl, apikey)
                endpoints['.epd'] = {}
                endpoints['.epd']['view'] = endpoints['.epd']['edit'] = appurl
                log.info('msg="Etherpad endpoints successfully configured" EtherpadURL="%s"' % appurl)
                return
        except ValueError:
            # bridge plugin could not be initialized
            pass
        except requests.exceptions.ConnectionError:
            pass

    # in all other cases, log failure
    log.error('msg="Attempted to register a non WOPI-compatible app" appurl="%s"' % appurl)


def initappsregistry():
    '''Initializes the CERNBox Office-like Apps Registry'''
    oos = config.get('general', 'oosurl', fallback=None)
    if oos:
        registerapp('MSOffice', oos, oos)
    code = config.get('general', 'codeurl', fallback=None)
    if code:
        registerapp('Collabora', code, code)
    codimd = config.get('general', 'codimdurl', fallback=None)
    codimdint = config.get('general', 'codimdinturl', fallback=None)
    if codimd:
        with open('/var/run/secrets/codimd_apikey') as f:
            apikey = f.readline().strip('\n')
            registerapp('CodiMD', codimd, codimdint, apikey)
    etherpad = config.get('general', 'etherpadurl', fallback=None)
    etherpadint = config.get('general', 'etherpadinturl', fallback=None)
    if etherpad:
        with open('/var/run/secrets/etherpad_apikey') as f:
            apikey = f.readline().strip('\n')
            registerapp('Etherpad', etherpad, etherpadint, apikey)
