##
## client.py: Dropbox @ CSCI1660 (Spring 2022)
##
## This is the file where all of your code for your Dropbox client
## implementation must go.
##

## WARNING: You MUST NOT change these default imports. If you change the default
##          import statements in the stencil code, your implementation will be
##          rejected by the autograder. (Our autograder actually enforces this
##          this correctly, as opposed to the Crewmate Academy's autograder
##          from the Handin project!)

# Optional library containing some helpful string constants; not required to use
# this in your implementation. See https://docs.python.org/3/library/string.html
# for usage and documentation.
import string

# Imports the `crypto` and `util` libraries. See the Dropbox Wiki for usage and
# documentation.
import support.crypto as crypto
import support.util as util

# Imports the `dataserver`, `keyserver`, and `memloc` instances. See the Dropbox
# Wiki for usage and documentation.
from support.dataserver import Memloc, dataserver, memloc
from support.keyserver import keyserver

# DO NOT EDIT ABOVE THIS LINE ##################################################

class User:
    def __init__(self, root_key, root) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """
        self.root_key = root_key
        self.root = root

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/upload-file.html
        """
        # TODO: Implement!
        #key = ...
        #share_root = ...
        encrypted_data = crypto.SymmetricEncrypt(key, crypto.SecureRandom(16), data)
        # Compute MAC/Digital Signature here
        data_memloc = Memloc.Make()
        dataserver.Set(data_memloc, encrypted_data)
        file = {"data_memloc": data_memloc, "filename": filename, "encryption_key": key, "share_tree": share_root}
        encrypted_file = crypto.AsymmetricEncrypt(self.encryption_public_key, util.ObjectToBytes(file))
        signature = crypto.SignatureSign(self.signing_key, encrypted_file)
        file_bytes = util.ObjectToBytes((encrypted_file, signature))
        # Store the file in a memloc and save location to user's root structure
    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/download-file.html
        """
        # TODO: Implement!
        file_bytes = dataserver.Get(self.file_locations[filename])
        file_with_sig = util.BytesToObject(file_bytes)
        valid = crypto.SignatureVerify(self.signing_key, file_with_sig[0], file_with_sig[1])
        if not valid:
            raise util.DropboxError("Could not validate file signature")
        file_bytes = crypto.AsymmetricDecrypt(self.encryption_key, file_with_sig[0])
        file = util.BytesToObject(file_bytes)
        data = crypto.SymmetricDecrypt(file["key"], dataserver.Get(file["data_memloc"]))
        # Check data integrity here
        return data

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/append-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/share-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/receive-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/revoke-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

def create_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/create-user.html
    """
    return authenticate_user(username, password)

def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/authenticate-user.html
    """

    salt = username.encode("ascii") + b"super secret academy salt"
    init_key = crypto.PasswordKDF(password, salt, 16)

    init_ptr = crypto.PasswordKDF("homedir", salt, 16)
    root = None
    root_key = None
    try:
        print(" * Authenticating current user")
        init = util.BytesToObject(
            crypto.SymmetricDecrypt(
                init_key,
                dataserver.Get(init_ptr)
            )
        )
        root_key = init["root_key"]
        root = util.BytesToObject(
            crypto.SymmetricDecrypt(
                root_key,
                dataserver.Get(init["root_ptr"])
            )
        )
    except:
        print(" * Setting up new user")
        root_ptr = crypto.SecureRandom(16)
        root_key = crypto.SecureRandom(16)

        init = {"root_ptr": root_ptr, "root_key": root_key}
        dataserver.Set(init_ptr,
            crypto.SymmetricEncrypt(
                init_key,
                crypto.SecureRandom(16),
                util.ObjectToBytes(init)
            )
        )
        root = {"nodes": 0, "tree": {}}
        dataserver.Set(root_ptr,
            crypto.SymmetricEncrypt(
                root_key,
                crypto.SecureRandom(16),
                util.ObjectToBytes(root)
            )
        )

    return User(root_key, root)

