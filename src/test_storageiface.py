'''
test_storageiface.py

Basic unit testing of the storage interfaces
'''

import unittest
import logging
import configparser

class TestStorage(unittest.TestCase):
  '''Simple tests for the storage layers of the WOPI server'''
  endpoint = '123e4567-e89b-12d3-a456-426655440000'
  userid = 'einstein'
  storage = None

  def __init__(self, *args, **kwargs):
    '''One-off initialization of the test environment: create mock logging and import the library'''
    super(TestStorage, self).__init__(*args, **kwargs)
    loghandler = logging.FileHandler('/var/log/wopi/wopiserver.log')
    loghandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s[%(process)d] %(levelname)-8s %(message)s',
                                              datefmt='%Y-%m-%dT%H:%M:%S'))
    log = logging.getLogger('wopiserver.test')
    log.addHandler(loghandler)
    log.setLevel(logging.DEBUG)
    # read the configuration
    config = configparser.ConfigParser()
    try:
      with open('/etc/wopi/wopiserver.defaults.conf') as fdef:
        config.read_file(fdef)
      config.read('/etc/wopi/wopiserver.conf')
      storagetype = config.get('general', 'storagetype')
    except (KeyError, configparser.NoOptionError):
      print("Missing option or missing configuration, check your /etc/wopi/wopiserver.conf file")
      raise

    # this is taken from wopiserver.py::storage_layer_import
    if storagetype in ['local', 'xroot', 'cs3']:
      storagetype += 'iface'
    else:
      raise ImportError('Unsupported/Unknown storage type %s' % storagetype)
    try:
      self.storage = __import__(storagetype, globals(), locals())
      self.storage.init(config, log)
    except ImportError:
      print("Missing module when attempting to import {}. Please make sure dependencies are met.", storagetype)
      raise


  def test_stat(self):
    '''Call stat() and assert the path matches'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')
    #self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_stat_fileid(self):
    '''Call stat() and assert the path matches'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    fileid = statInfo['inode'].split(':')
    self.assertEqual(len(fileid), 2, 'This storage interface does not support stat by fileid')
    statInfo = self.storage.stat(fileid[0], fileid[1], self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')
    #self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_stat_nofile(self):
    '''Call stat() and assert the exception is as expected'''
    with self.assertRaises(IOError):
      self.storage.stat(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_statx(self):
    '''Call statx() and assert the path matches'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    statInfo = self.storage.statx(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')
    #self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_readfile(self):
    '''Writes a file and reads it back, validating that the content matches'''
    content = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, content)
    content = ''
    for chunk in self.storage.readfile(self.endpoint, '/test.txt', self.userid):
      self.assertNotIsInstance(chunk, IOError, 'raised by storage.readfile')
      content += chunk.decode('utf-8')
    self.assertEqual(content, 'bla\n', 'File test.txt should contain the string "bla"')
    #self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_read_nofile(self):
    '''Test reading of a non-existing file'''
    read = next(self.storage.readfile(self.endpoint, '/hopefullynotexisting', self.userid))
    self.assertIsInstance(read, IOError, 'readfile returned %s' % read)
    self.assertEqual(str(read), 'No such file or directory', 'readfile returned %s' % read)

  def test_write_remove(self):
    '''Test write and removal of a file'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    self.storage.writefile(self.endpoint, '/testwrite', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/testwrite', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.storage.removefile(self.endpoint, '/testwrite', self.userid)
    with self.assertRaises(IOError):
      self.storage.stat(self.endpoint, '/testwrite', self.userid)

  def test_remove_nofile(self):
    '''Test removal of a non-existing file'''
    with self.assertRaises(IOError):
      self.storage.removefile(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_xattr(self):
    '''Test all xattr methods'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    self.storage.setxattr(self.endpoint, '/test.txt', self.userid, 'testkey', 'testvalue')
    v = self.storage.getxattr(self.endpoint, '/test.txt', self.userid, 'testkey')
    self.assertEqual(v, b'testvalue')
    self.storage.rmxattr(self.endpoint, '/test.txt', self.userid, 'testkey')
    v = self.storage.getxattr(self.endpoint, '/test.txt', self.userid, 'testkey')
    self.assertEqual(v, None)
    #self.storage.removefile(self.endpoint, '/test.txt', self.userid)

  def test_rename(self):
    '''Test renaming and stat of a file'''
    buf = b'bla\n'
    self.storage.writefile(self.endpoint, '/test.txt', self.userid, buf)
    self.storage.renamefile(self.endpoint, '/test.txt', '/test_renamed.txt', self.userid)
    statInfo = self.storage.stat(self.endpoint, '/test_renamed.txt', self.userid)
    self.assertEqual(statInfo['filepath'], '/test_renamed.txt')
    self.storage.renamefile(self.endpoint, '/test_renamed.txt', '/test.txt', self.userid)
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertEqual(statInfo['filepath'], '/test.txt')
    #self.storage.removefile(self.endpoint, '/test.txt', self.userid)


if __name__ == '__main__':
  unittest.main()
