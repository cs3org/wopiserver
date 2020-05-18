# Basic unit testing of the storage interfaces
#

import unittest

class TestStorage(unittest.TestCase):
  '''Simple tests for the storage layers of the WOPI server'''
  storagetype = 'cs3'    # TODO initialize from something
  endpoint = '123e4567-e89b-12d3-a456-426655440000'
  userid = 'einstein'
  storage = None

  def setUp(self):
    '''Setup the test: this is taken from wopiserver.py::storage_layer_import'''
    if self.storagetype in ['local', 'xroot', 'cs3']:
      self.storagetype += 'iface'
    else:
      raise ImportError('Unsupported/Unknown storage type %s' % self.storagetype)
    try:
      self.storage = __import__(self.storagetype, globals(), locals())
      self.storage.init(None)
    except ImportError:
      print("Missing module when attempting to import {}. Please make sure dependencies are met.", self.storagetype)
      raise

  def test_stat(self):
    '''Call stat() and assert the path matches'''
    statInfo = self.storage.stat(self.endpoint, '/test.txt', self.userid)
    self.assertIsInstance(statInfo, dict)
    self.assertEqual(statInfo['filepath'], '/test.txt', 'Filepath should be /test.txt')

  def test_stat_nofile(self):
    '''Call stat() and assert the exception is as expected'''
    with self.assertRaises(IOError):
      self.storage.stat(self.endpoint, '/hopefullynotexisting', self.userid)

  def test_readfile(self):
    '''Assume a test.txt file exists with content = "bla"'''
    content = ''
    for l in self.storage.readfile(self.endpoint, '/test.txt', self.userid):
      content += l.encode('utf-8')
    self.assertEqual(content, 'bla', 'File test.txt should contain the string "bla"')

  def test_writefile(self):
    '''Write some stuff to a file and assert the file is created'''
    buf = b'ebe5tresbsrdthbrdhvdtr'
    self.storage.writefile(self.endpoint, '/testwrite', self.userid, buf)
    statInfo = self.storage.stat(self.endpoint, '/testwrite', self.userid)
    self.assertIsInstance(statInfo, dict)

if __name__ == '__main__':
  unittest.main()
