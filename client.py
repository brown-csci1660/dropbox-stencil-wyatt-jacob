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
from multiprocessing.sharedctypes import Value
import string

# Imports the `crypto` and `util` libraries. See the Dropbox Wiki for usage and
# documentation.
from typing import Union, Any

import support.crypto as crypto
import support.util as util

# Imports the `dataserver`, `keyserver`, and `memloc` instances. See the Dropbox
# Wiki for usage and documentation.
from support.dataserver import Memloc, dataserver, memloc
from support.keyserver import keyserver

# DO NOT EDIT ABOVE THIS LINE ##################################################

class User:
    def __init__(self, username, root_key, pk, sk) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """
        self.username = username
        self.root_key = root_key
        self.pk = pk
        self.sk = sk
        # Are we allowed to add private helper methods?  (such as maybe to refactor duplicate code?)

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/upload-file.html
        """

        old_ptr = None
        old_key = None
        owner = None
        old_share_tree = None
        try:
            # Get the old attributes here in case we are updating a file that has preëxisting metadata.
            old_metadata = self.__download_file(filename, whence="metadata only")
            old_ptr = old_metadata["ptr"]
            old_key = old_metadata["key"]
            owner = old_metadata["owner"]
            old_share_tree = old_metadata["share_tree"]
        except util.DropboxError:
            # It is okay to overwrite any old (potentially corrupted) data now.
            pass

        metadata = {
            "filename": filename,  # checked later to prevent moving-copying attacks
            "ptr": old_ptr or crypto.SecureRandom(16),  # preserve old ptr if it exists
            "key": old_key or crypto.SecureRandom(16),  # preserve old key if it exists
            "owner": owner or self.username,
            "share_tree": old_share_tree or memloc.Make()  # preserve old share_tree if it exists
        }

        # Encrypt and sign file header
        ptr = metadata["ptr"]
        ctr_max = int.to_bytes(1, 16, 'little')
        encrypted_header = crypto.SymmetricEncrypt(metadata["key"], crypto.SecureRandom(16), ctr_max)
        header_signature = crypto.HMAC(metadata["key"], encrypted_header)
        dataserver.Set(ptr, encrypted_header)
        dataserver.Set(ptr[-1:] + ptr[:-1], header_signature)

        # Encrypt and sign file data
        ptr = int.to_bytes(int.from_bytes(ptr, 'little')+1, 16, 'little')
        ctr = int.to_bytes(1, 16, 'little')
        encrypted_data = crypto.SymmetricEncrypt(metadata["key"], crypto.SecureRandom(16), ctr+data)
        data_signature = crypto.HMAC(metadata["key"], encrypted_data)
        dataserver.Set(ptr, encrypted_data)
        dataserver.Set(ptr[-1:] + ptr[:-1], data_signature)

        self.__save_metadata__(metadata)

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/download-file.html
        """
        return self.__download_file(filename, whence="file contents")

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/append-file.html
        """

        metadata, header = None, None
        try:
            metadata, header_bytes = self.__download_file(filename, whence="metadata and header only")
        except util.DropboxError:
            raise util.DropboxError("Could not open file for appending or file does not exist.")

        parts_count = int.from_bytes(header_bytes, 'little')

        ctr = int.to_bytes(1+parts_count, 16, 'little')

        # Encrypt and sign file header
        ptr = metadata["ptr"]
        ctr_max = ctr
        encrypted_header = crypto.SymmetricEncrypt(metadata["key"], crypto.SecureRandom(16), ctr_max)
        header_signature = crypto.HMAC(metadata["key"], encrypted_header)
        dataserver.Set(ptr, encrypted_header)
        dataserver.Set(ptr[-1:] + ptr[:-1], header_signature)

        # Encrypt and sign file data
        ptr = int.to_bytes(int.from_bytes(ptr, 'little')+parts_count+1, 16, 'little')
        ctr = ctr
        encrypted_data = crypto.SymmetricEncrypt(metadata["key"], crypto.SecureRandom(16), ctr+data)
        data_signature = crypto.HMAC(metadata["key"], encrypted_data)
        dataserver.Set(ptr, encrypted_data)
        dataserver.Set(ptr[-1:] + ptr[:-1], data_signature)

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/share-file.html
        """
        recipient_pk = None
        try:
            recipient_pk = keyserver.Get(recipient)
        finally:
            if not recipient_pk:
                raise util.DropboxError("No such recipient exists!")

        metadata = None
        try:
            metadata, _ = self.__download_file(filename, whence="metadata and header only")
            # metadata = self.__download_file(filename, whence="metadata only")
        except util.DropboxError:
            raise util.DropboxError("Failed to first open the file locally.")

        def add_share(parent, children): 
            if parent == self.username:
                 return children + [[recipient, memloc.Make()]]
            else:
                return children
        self.__traverse_share_tree__(metadata["share_tree"], metadata["owner"], local_node_callback=add_share)

        self.__save_metadata__(metadata, share_to=recipient)

    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/receive-file.html
        """
        sender_pk = None
        try:
            sender_pk = keyserver.Get(sender)
        finally:
            if not sender_pk:
                raise util.DropboxError("No such sender exists!")

        existing_local_file_metadata = None
        try:
            existing_local_file_metadata = self.__download_file(filename, whence="metadata only")
        except util.DropboxError:
            pass  # We expect this, that there shouldn't already be a local file of the same name.
        finally:
            if existing_local_file_metadata and existing_local_file_metadata["owner"] == self.username:  # test second clause
                raise util.DropboxError("There is a local file with that same name.  Aborting for its protection, as to not overwrite.")

        metadata, err = self.__read_metadata__(filename, sender)
        if metadata is None:
            raise util.DropboxError("Failed to receive file from sender: " + err)

        self.__save_metadata__(metadata)

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/revoke-file.html
        """
        old_recipient_pk = None
        try:
            old_recipient_pk = keyserver.Get(old_recipient)
        finally:
            if not old_recipient_pk:
                raise util.DropboxError("No such old recipient exists!")
        # self.delete_file(filename, old_recipient, old_recipient_pk, whence="metadata only", owner_is_recipient=True)  # delete old intermediate meta
        try:
            dataserver.Delete(crypto.HashKDF(crypto.Hash(self.username.encode()+old_recipient.encode()), filename)[:16])
            pass
        except ValueError:
            raise util.DropboxError("File corrupted before deletion (as part of the revocation process) could proceed.")
        del old_recipient_pk    

        share_tree = None
        old_ptr = None
        owner = None
        try:
            old_metadata = self.__download_file(filename, whence="metadata only")
            owner = old_metadata["owner"]
            share_tree = old_metadata["share_tree"]
            old_ptr = old_metadata["ptr"]
        except util.DropboxError:
            raise util.DropboxError("Failed to open and retrieve file's share tree.")

        def rm_share(parent, children):
            if parent == self.username:
                return list(filter(lambda x: x[0] != old_recipient, children))
            else:
                return children
        self.__traverse_share_tree__(share_tree, owner, local_node_callback=rm_share)

        data = self.download_file(filename)
        # self.upload_file(filename, b"file " + filename.encode() + b" has been deleted")
        self.delete_file(filename)
        self.upload_file(filename, data)  # (re)upload with a different key

        metadata = None
        try:
            metadata = self.__download_file(filename, whence="metadata only")
        except util.DropboxError:
            raise util.DropboxError("Failed to retrieve file's new metadata.")

        metadata["share_tree"] = share_tree
        self.__save_metadata__(metadata)
        def update_share(usr, children):
            self.__save_metadata__(metadata, share_to = usr)
            return children
        self.__traverse_share_tree__(metadata["share_tree"], metadata["owner"], update_share)

    def __download_file(self, filename: str, owner=None, owner_pk=None, whence="file contents") -> Union[Union[object, bytes, int], Any]:
        err2 = ""
        metadata, err1 = self.__read_metadata__(filename)
        if metadata is not None:
            source_metadata, err2 = self.__read_metadata__(filename, metadata["owner"])
            if metadata != source_metadata and source_metadata is not None:
                metadata = source_metadata
                self.__save_metadata__(metadata)
        if metadata is None:
            raise util.DropboxError("Could not find valid metadata for file | " + str(err1) + " : " + str(err2))
        if whence == "metadata only":
            return metadata
        # else:

        data_parts = []
        try:
            i = int.from_bytes(metadata["ptr"], 'little')
            ptr = metadata["ptr"]
            key = metadata["key"]
            while self.isSet(ptr) and (not whence == "metadata and header only" or ptr == metadata["ptr"]):  # when *"header only" is set, the loop body is only run once, as the header will be data_part[0]
                dataserver_Get_ptr_ = dataserver.Get(ptr)
                valid = (
                        crypto.HMAC(key, dataserver_Get_ptr_) ==
                        dataserver.Get(ptr[-1:] + ptr[:-1])  # data_signature
                )
                if not valid:
                    raise util.DropboxError("Failed to verify file integrity.")
                else:
                    data_parts.append(crypto.SymmetricDecrypt(
                        key,
                        dataserver_Get_ptr_  # cache get to prevent race condition vulnerability
                    ))

                i = i + 1
                ptr = int.to_bytes(i, 16, 'little')
        finally:
            if len(data_parts) == 0:
                raise util.DropboxError("Failed to decrypt file data.\nFile access was revoked (either legitimately or maliciously).")  # TODO: we can edit this to distinguish between those two cases
            elif len(data_parts) == 1:
                if whence == "metadata and header only":
                    header: bytes
                    [header] = data_parts  # we have only read the 16-byte header, and none of the actual contents
                    return metadata, header
                else:
                    raise util.DropboxError(whence+str(len(data_parts))+"Only a header was found - no actual data remains.  Boycott the Dataserver!")

        data = b""  # data = None
        try:
            header, parts = data_parts[0], data_parts[1:]
            assert (len(header) == 16)
            parts_count = int.from_bytes(header, 'little')
            assert (len(parts) == parts_count)
            # data = b""
            for ctr, part in enumerate(parts, 1):  # enumerate(data_parts)[1:]
                idx, part_data = int.from_bytes(part[:16], 'little'), part[16:]
                assert (idx == ctr)  # enforce original intended ordering
                data = data + part_data
        except AssertionError:
            raise util.DropboxError("Failed to verify file integrity.")

        return data

    def delete_file(self, filename: str, owner=None, owner_pk=None, whence="file and metadata"):
        try:
            metadata = None
            if whence == "file and metadata":
                metadata, header_bytes = self.__download_file(filename, owner=owner, whence="metadata and header only")

                header_ptr = metadata["ptr"]
                header_ptr_int = int.from_bytes(header_ptr, 'little')
                parts_count = int.from_bytes(header_bytes, 'little')
                for i in range(header_ptr_int, header_ptr_int+parts_count):
                    ptr = int.to_bytes(i, 16, 'little')
                    dataserver.Delete(ptr)  # destroy header and then all following data blocks
            else:  # if whence == "metadata only"
                metadata = self.__download_file(filename, owner, owner_pk, whence)#="metadata only")

            ptr_metadata = (
                crypto.HashKDF(crypto.Hash(owner.encode() + self.username.encode()), filename)[:16]
                if owner else
                crypto.HashKDF(self.root_key, filename)
            )
            dataserver.Delete(ptr_metadata)  # delete metadata
        except ValueError:
            raise util.DropboxError("File corrupted before deletion could proceed.")
    
    def isSet(self, ptr):
        try:
            dataserver.Get(ptr)
            return True
        except ValueError:
            return False

    def HybridEncryptAndSign(self, pk, data, sk=None):  # encryption key, data, secret (signing) key
        sk = sk or self.sk
        """ hybrid encryption start "'"
        encrypted_data = crypto.AsymmetricEncrypt(self.pk, util.ObjectToBytes(data))
        """
        ephemeral, iv = crypto.SecureRandom(16), crypto.SecureRandom(16)
        encrypted_data = crypto.AsymmetricEncrypt(pk, ephemeral) + crypto.SymmetricEncrypt(ephemeral, iv, util.ObjectToBytes(data))
        """ hybrid encryption  end  """
        data_signature = crypto.SignatureSign(crypto.SignatureSignKey(sk.libPrivKey), encrypted_data)
        return encrypted_data, data_signature

    def HybridDecrypt(self, sk, encrypted_data):#, data_signature, pk=None):  # decryption key, data, public (verification) key   #AndVerify   # pk = pk or self.pk
        """ hybrid decryption start "'"
        metadata = util.BytesToObject(
            crypto.AsymmetricDecrypt(
                self.sk,
                encrypted_metadata
            )
        )
        """
        data = util.BytesToObject(
            crypto.SymmetricDecrypt(
                crypto.AsymmetricDecrypt(
                    sk,
                    encrypted_data[:2048 // 8]
                ), encrypted_data[2048 // 8:]
            )
        )
        """ hybrid decryption  end  """
        return data

    def __traverse_share_tree__(self, share_tree_ptr, parent, local_node_callback=None):
        share_tree = None
        try:
            share_tree = util.BytesToObject(dataserver.Get(share_tree_ptr))
            pk = keyserver.Get(parent)
            valid = crypto.SignatureVerify(crypto.SignatureVerifyKey(pk.libPubKey), util.ObjectToBytes(share_tree["children"]), share_tree["signature"])
            if not valid:
                raise util.DropboxError("Integrity violation in share tree")
        except ValueError:
            share_tree = {"children":[], "signature":None}

        for child in share_tree["children"]:
            name = child[0]
            child_ptr = child[1]
            self.__traverse_share_tree__(child_ptr, name, local_node_callback)
        if local_node_callback is not None:
                new_children = local_node_callback(parent, share_tree["children"])
                if new_children != share_tree["children"]:
                    share_tree["children"] = new_children
                    share_tree["signature"] = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey), util.ObjectToBytes(share_tree["children"]))
                    dataserver.Set(share_tree_ptr, util.ObjectToBytes(share_tree))

    def __read_metadata__(self, filename, share_source=None):
        encrypted_metadata = None
        metadata_signature = None
        source = crypto.HashKDF(self.root_key, filename)
        if share_source is not None:
            source = crypto.HashKDF(crypto.Hash(share_source.encode()+self.username.encode()), filename)[:16]
        try:
            encrypted_metadata, metadata_signature = util.BytesToObject(dataserver.Get(source))
        except:
            return None, "No entry in database"
        pk = self.pk if share_source is None else keyserver.Get(share_source)
        valid = crypto.SignatureVerify(
            crypto.SignatureVerifyKey(pk.libPubKey),
            encrypted_metadata,
            metadata_signature
        )
        if not valid:
            return None, "signature not valid"
        metadata = None
        try:
            metadata = self.HybridDecrypt(self.sk, encrypted_metadata)
            assert (metadata["filename"] == filename)  # protect against a moved-metadata attack
        except:
            return None, "failed to decrypt"
        return metadata, None

    def __save_metadata__(self, metadata, share_to=None):
        filename = metadata["filename"]
        pk = self.pk if share_to is None else keyserver.Get(share_to)

        dest = crypto.HashKDF(self.root_key, filename)
        if share_to is not None:
            dest = crypto.HashKDF(crypto.Hash(self.username.encode()+share_to.encode()), filename)[:16]
        # Encrypt and sign file metadata
        encrypted_metadata, metadata_signature = self.HybridEncryptAndSign(pk, metadata, self.sk)
        # Store the file in a memloc and save location to user's root structure
        file_bytes = util.ObjectToBytes([encrypted_metadata, metadata_signature])
        dataserver.Set(
            dest,
            file_bytes
        )

        
    @classmethod
    def __write_root__(cls, ptr, data, k, sk):  # symmetric key, k, and asymmetric secret (signing) key, sk
        dataserver.Set(ptr,
           crypto.SymmetricEncrypt(
               k,
               crypto.SecureRandom(16),
               util.ObjectToBytes(data)
           )
        )  # set data
        dataserver.Set(ptr[-1:]+ptr[:-1],
            crypto.SignatureSign(
                crypto.SignatureSignKey(sk.libPrivKey),
                dataserver.Get(ptr),
            )
        )  # sign data

    @classmethod
    def __read_root__(cls, ptr, k, pk):
        dataserver_Get_ptr_ = dataserver.Get(ptr)
        data_opt = None
        try:
            data_opt = util.BytesToObject(
                crypto.SymmetricDecrypt(
                    k,
                    dataserver_Get_ptr_
                )
            )
        except:
            raise util.DropboxError("Decryption failed!  Invalid password?")

        sig = dataserver.Get(ptr[-1:]+ptr[:-1])
        valid = crypto.SignatureVerify(crypto.SignatureVerifyKey(pk.libPubKey), dataserver_Get_ptr_, sig)
        if not valid or not data_opt:
            raise util.DropboxError("Integrity violation")
        else:
            return data_opt


def create_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/create-user.html
    """

    pk, sk = crypto.AsymmetricKeyGen()

    try:
        keyserver.Set("", None)
    except ValueError: pass

    try:
        keyserver.Set(username, pk)
    except ValueError:
        raise util.DropboxError("That username is not available!")

    salt = username.encode("ascii") + b"super secret academy salt"
    root_ptr = crypto.PasswordKDF("usrdir", salt, 16)
    root_key = crypto.PasswordKDF(password, salt, 16)

    User.__write_root__(root_ptr, bytes(sk), root_key, sk)

    return authenticate_user(username, password)


def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/authenticate-user.html
    """

    pk = None
    try:
        pk = keyserver.Get(username)
    finally:
        if not pk: raise util.DropboxError("Invalid username!")

    salt = username.encode("ascii") + b"super secret academy salt"
    root_ptr = crypto.PasswordKDF("usrdir", salt, 16)
    root_key = crypto.PasswordKDF(password, salt, 16)

    sk = crypto.AsymmetricDecryptKey.from_bytes(User.__read_root__(root_ptr, root_key, pk))

    return User(username, root_key, pk, sk)
