##
## test_client.py: Dropbox @ CSCI1660 (Spring 2022)
##
## This is the file where all of your test cases for your Dropbox client
## implementation must go.
##

## WARNING: You MUST NOT change these default imports. If you change the default
##          import statements in the stencil code, your implementation will be
##          rejected by the autograder. (Our autograder ~actually~ enforces this
##          this correctly, as opposed to the Crewmate Academy's autograder
##          from the Handin project!)

import unittest
import string

import support.crypto as crypto
import support.util as util

from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

from client import create_user, authenticate_user, User

# DO NOT EDIT ABOVE THIS LINE ##################################################

class ClientTests(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_create_user(self):
        """
        Checks user creation.
        """
        u = create_user("usr", "pswd")
        u2 = authenticate_user("usr", "pswd")

        self.assertEqual(vars(u), vars(u2))

    def test_authenticate_user_error(self):
        self.assertRaises(util.DropboxError, lambda: authenticate_user("usr", "pswd"))

        # Run again to check that authenticate_user doesn't silently create a new user
        self.assertRaises(util.DropboxError, lambda: authenticate_user("usr", "pswd"))

        # Finally check that the username is still valid for future use
        u = create_user("usr", "pswd")
        u2 = authenticate_user("usr", "pswd")
        self.assertEqual(vars(u), vars(u2))

    def test_empty_username(self):
        self.assertRaises(util.DropboxError, lambda: create_user("", "pswd"))

    def test_authenticate_user_wrong_password(self):
        u = create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: authenticate_user("usr", ""))

    def test_whitespace_username(self):
        u = create_user(" ", "pswd")
        self.assertRaises(util.DropboxError, lambda: authenticate_user("", "pswd"))

    def test_upload(self):
        """
        Tests if uploading a file throws any errors.
        """
        u = create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')

    def test_download(self):
        """
        Tests if a downloaded file has the correct data in it.
        """
        u = create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_append(self):
        """
        Tests if a downloaded file has the correct data in it after appending data.
        """
        u = create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'
        data_to_be_appended = b' and appended data'

        u.upload_file("file1", data_to_be_uploaded)
        u.append_file("file1", data_to_be_appended)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded + data_to_be_appended)

    def test_share_and_download(self):
        """
        Simple test of sharing and downloading a shared file.
        """
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

    def test_share_update_and_download(self):
        """
        Simple test of sharing, updating, then downloading a shared file.
        """
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")
        u1.upload_file("shared_file", b'NEW shared data')

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'NEW shared data')

        #--- now test again, but with the update occurring AFTER the recieve ---
        self.setUp()

        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")

        u1.upload_file("shared_file", b'NEW shared data')

        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'NEW shared data')

    def test_share_append_and_download(self):
        """
        Simple test of sharing, appending, and then downloading a shared file.
        """
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        data_to_be_uploaded = b'sharing-owner\'s data'
        data_to_be_appended_u1 = b' and sharing-owner\'s appended data'
        data_to_be_appended_u2 = b' and recipient\'s appended data'

        u1.upload_file("shared_file", data_to_be_uploaded)
        """ test intermittent downloading """; u1.download_file("shared_file")
        u1.share_file("shared_file", "usr2")
        """ test intermittent downloading """; u1.download_file("shared_file")
        u1.append_file("shared_file", data_to_be_appended_u1)
        """ test intermittent downloading """; u1.download_file("shared_file")

        u2.receive_file("shared_file", "usr1")
        """ test intermittent downloading """; u1.download_file("shared_file")
        u2.append_file("shared_file", data_to_be_appended_u2)

        downloaded_data_u1 = u1.download_file("shared_file")
        downloaded_data_u2 = u2.download_file("shared_file")

        # Assert Consistency
        self.assertEqual(downloaded_data_u1, downloaded_data_u2)

        # Assert Correctness
        self.assertEqual(downloaded_data_u1, data_to_be_uploaded + data_to_be_appended_u1 + data_to_be_appended_u2)
        self.assertEqual(downloaded_data_u2, data_to_be_uploaded + data_to_be_appended_u1 + data_to_be_appended_u2)

    def test_revoke(self):
        """
        Tests the sharing and revoking a shared file.
        """
        u_alice = create_user("Alice", "iamalice")
        u_bob = create_user("Bob", "iambob")
        u_eleanor = create_user("Eleanor", "iameleanor")

        # Alice shares a file with Bob and Eleanor
        u_alice.upload_file("shared_file", b'shared data')
        u_alice.share_file("shared_file", "Bob")
        u_alice.share_file("shared_file", "Eleanor")

        # Bob receives that shared file from Alice
        u_bob.receive_file("shared_file", "Alice")
        down_data = u_bob.download_file("shared_file")
        self.assertEqual(down_data, b'shared data')

        # Eleanor receives that shared file from Alice
        u_eleanor.receive_file("shared_file", "Alice")
        down_data = u_eleanor.download_file("shared_file")
        self.assertEqual(down_data, b'shared data')

        # Alice revokes Eleanor's access of this file
        u_alice.revoke_file("shared_file", "Eleanor")

        # Bob downloads the file again later which should still be available and up-to-date
        down_data = u_bob.download_file("shared_file")
        self.assertEqual(down_data, b'shared data')

        # Eleanor tries to download the file again later and finds it to be unavailable.
        self.assertRaises(util.DropboxError, lambda: u_eleanor.download_file("shared_file"))

    def test_download_error(self):
        """
        Simple test that tests that downloading a file that doesn't exist
        raise an error.
        """
        u = create_user("usr", "pswd")

        # NOTE: When using `assertRaises`, the code that is expected to raise an
        #       error needs to be passed to `assertRaises` as a thunk.
        self.assertRaises(util.DropboxError, lambda: u.download_file("file1"))

    def test_revoke_subtree(self):
        """
        Check that revokation apllies to the whole subtree of the revoked user
        """
        usr1 = create_user("usr1", "psw1")
        usr2 = create_user("usr2", "psw3")
        usr3 = create_user("usr3", "psw3")
        usr4 = create_user("usr4", "psw4")
        usr5 = create_user("usr5", "psw5")

        usr1.upload_file("shared_file", b"file data")
        usr1.share_file("shared_file", "usr2")
        usr1.share_file("shared_file", "usr3")
        usr2.receive_file("shared_file", "usr1")
        usr3.receive_file("shared_file", "usr1")

        usr3.share_file("shared_file", "usr4")
        usr4.receive_file("shared_file", "usr3")
        usr4.share_file("shared_file", "usr5")
        usr5.receive_file("shared_file", "usr4")

        self.assertEqual(usr5.download_file("shared_file"), b"file data")

        usr1.revoke_file("shared_file", "usr3")
        self.assertEqual(usr2.download_file("shared_file"), b"file data")
        self.assertRaises(util.DropboxError, lambda: usr5.download_file("shared_file"))

    def test_missing_receive_file_call(self):
        usr1 = create_user("usr1", "pswd1")
        usr2 = create_user("usr2", "pswd2")

        usr1.upload_file("shared_file", b"some file data")
        usr1.share_file("shared_file", "usr2")

        self.assertRaises(util.DropboxError, lambda: usr2.download_file("shared_file"))

    def test_receive_without_share(self):
        usr1 = create_user("usr1", "pswd1")
        usr2 = create_user("usr2", "pswd2")

        usr1.upload_file("shared_file", b"some file data")
        thunk = lambda: usr2.receive_file("shared_file", "usr1")
        self.assertRaises(util.DropboxError, thunk)

    def test_receive_dup_filename(self):
        usr1 = create_user("usr1", "pswd1")
        usr2 = create_user("usr2", "pswd2")
        usr3 = create_user("usr3", "pswd3")

        usr1.upload_file("shared_file", b"some file data")
        usr2.upload_file("shared_file", b"some other data")

        usr2.share_file("shared_file", "usr3")
        usr3.receive_file("shared_file", "usr2")

        usr1.share_file("shared_file", "usr2")
        #usr2.receive_file("shared_file", "usr1")

        # this call should error because "shared_file" already exists
        #self.assertRaises(util.DropboxError, lambda: usr2.receive_file("shared_file", "usr1"))

        # usr3 should lose access to usr2's overwritten file
        #self.assertRaises(util.DropboxError, lambda: usr3.download_file("shared_file"))
        # usr3 should not be able to regain access by calling receive_file() again
        #self.assertRaises(util.DropboxError, lambda: usr3.receive_file("shared_file", "usr2"))

    def test_append_to_revoked_file(self):
        usr1 = create_user("usr1", "pswd1")
        usr2 = create_user("usr2", "pswd2")

        usr1.upload_file("shared_file", b"some data")
        usr1.share_file("shared_file", "usr2")

        usr2.receive_file("shared_file", "usr1")

        usr1.revoke_file("shared_file", "usr2")

        self.assertRaises(util.DropboxError, lambda: usr2.append_file("shared_file", b"more data"))

    def test_early_revoke(self):
        usr1 = create_user("usr1", "pswd1")
        usr2 = create_user("usr2", "pswd2")

        usr1.upload_file("shared_file", b"some data")

        usr1.share_file("shared_file", "usr2")
        usr1.revoke_file("shared_file", "usr2")

        #self.assertRaises(util.DropboxError, lambda: usr2.receive_file("shared_file", "usr1"))

        self.assertRaises(util.DropboxError, lambda: usr2.download_file("shared_file"))

    def test_self_shared_shared_file(self):
        usr1 = create_user("usr1", "psw1")
        usr2 = create_user("usr2", "psw3")
        usr3 = create_user("usr3", "psw3")

        usr1.upload_file("shared_file", b"file data")

        usr1.share_file("shared_file", "usr2")
        usr2.receive_file("shared_file", "usr1")

        usr1.share_file("shared_file", "usr3")
        usr3.receive_file("shared_file", "usr1")

        usr3.share_file("shared_file", "usr3")


    #TODO:
        # test share_file with a file not owned by the calling user
        # test sharing multiple files
        # test that shares are unaffected by owner overwriting the file

# DO NOT EDIT BELOW THIS LINE ##################################################

if __name__ == '__main__':
    unittest.main()
