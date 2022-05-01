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

        ptr = None
        key = None
        share_tree = None
        try:
            encrypted_metadata, metadata_signature = (None, None)
            try:
                encrypted_metadata, metadata_signature = util.BytesToObject(
                    dataserver.Get(
                        crypto.HashKDF(self.root_key, filename),
                    )
                )
            finally:
                if not all([encrypted_metadata, metadata_signature]):
                    raise util.DropboxError("Deserialization failed.  File may have been tampered with!")

            valid = crypto.SignatureVerify(
                crypto.SignatureVerifyKey(self.pk.libPubKey),
                encrypted_metadata,
                metadata_signature
            )
            if not valid:
                raise util.DropboxError("Metadata integrity violation")

            metadata = None
            try:
                """ hybrid decryption start "'"
                metadata = util.BytesToObject(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata
                    )
                )
                """
                metadata = util.BytesToObject(
                    crypto.SymmetricDecrypt(
                        crypto.AsymmetricDecrypt(
                            self.sk,
                            encrypted_metadata[:2048 // 8]
                        ), encrypted_metadata[2048 // 8:]
                    )
                )
                """ hybrid decryption  end  """

                assert (metadata["filename"] == filename)  # protect against a moved-metadata attack
            finally:
                if not metadata:
                    raise util.DropboxError("Failed to decrypt metadata.")

            # Get the old attributes here in case we are updating a file that has preëxisting metadata.
            ptr = metadata["ptr"]
            key = metadata["key"]
            share_tree = metadata["share_tree"]
            # print("found old metadata")
        except util.DropboxError:
            # It is okay to overwrite any old (potentially corrupted) data now.
            pass

        metadata = {
            "filename": filename,  # checked later to prevent moving-copying attacks
            "ptr": ptr or crypto.SecureRandom(16),
            "key": key or crypto.SecureRandom(16),
            "share_tree": share_tree or {}
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

        # Encrypt and sign file metadata
        """ hybrid encryption start "'"
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, util.ObjectToBytes(metadata))
        """
        ephemeral, iv = crypto.SecureRandom(16), crypto.SecureRandom(16)
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, ephemeral) + crypto.SymmetricEncrypt(ephemeral, iv, util.ObjectToBytes(metadata))
        """ hybrid encryption  end  """
        metadata_signature = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey), encrypted_metadata)

        # Store the file in a memloc and save location to user's root structure
        file_bytes = util.ObjectToBytes([encrypted_metadata, metadata_signature])
        dataserver.Set(
            crypto.HashKDF(self.root_key, filename),
            file_bytes
        )

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/download-file.html
        """

        encrypted_metadata, metadata_signature = (None, None)
        try:
            encrypted_metadata, metadata_signature = util.BytesToObject(
                dataserver.Get(
                    crypto.HashKDF(self.root_key, filename),
                )
            )
        finally:
            if not all([encrypted_metadata, metadata_signature]):
                raise util.DropboxError("No such file exists.")

        valid = crypto.SignatureVerify(
            crypto.SignatureVerifyKey(self.pk.libPubKey),
            encrypted_metadata,
            metadata_signature
        )
        if not valid:
            raise util.DropboxError("Metadata integrity violation")

        metadata = None
        try:
            """ hybrid decryption start "'"
            metadata = util.BytesToObject(
                crypto.AsymmetricDecrypt(
                    self.sk,
                    encrypted_metadata
                )
            )
            """
            metadata = util.BytesToObject(
                crypto.SymmetricDecrypt(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata[:2048//8]
                    ),  encrypted_metadata[2048//8:]
                )
            )
            """ hybrid decryption  end  """

            assert(metadata["filename"] == filename)  # protect against a moved-metadata attack
        finally:
            if not metadata:
                raise util.DropboxError("Failed to decrypt metadata.")

        def isSet(ptr):
            try:
                dataserver.Get(ptr)
                return True
            except ValueError:
                return False

        data_parts = []
        try:
            i = int.from_bytes(metadata["ptr"], 'little')
            ptr = metadata["ptr"]
            key = metadata["key"]
            while isSet(ptr):
                dataserver_Get_ptr_ = dataserver.Get(ptr)
                valid = (
                    crypto.HMAC(key, dataserver_Get_ptr_) ==
                    dataserver.Get(ptr[-1:] + ptr[:-1])  # data_signature
                )
                if not valid:
                    if not "owner" in metadata:
                        raise util.DropboxError("Failed to verify file integrity.")
                    else:
                        valid = None
                        new_key = None
                        new_ptr = None
                        try:
                            encrypted_new_key, new_key_signature = util.BytesToObject(dataserver_Get_ptr_)

                            owner_pk = None
                            try:
                                owner_pk = keyserver.Get(metadata["owner"])
                            finally:
                                if not owner_pk:
                                    raise util.DropboxError("No such sender exists!")

                            valid = crypto.SignatureVerify(
                                crypto.SignatureVerifyKey(owner_pk.libPubKey),
                                encrypted_new_key,
                                new_key_signature
                            )

                            new_loc = crypto.AsymmetricDecrypt(
                                self.sk,
                                encrypted_new_key
                            )
                            assert(len(new_loc) == 32)
                            new_key, new_ptr = new_loc[:16], new_loc[16:]

                            assert valid
                        finally:
                            if not valid:
                                raise util.DropboxError("File access was revoked (either legitimately or maliciously).")  # TDO: we can edit this to distinguish between those two cases
                            #else:


                        # Update key and location, then write updated metadata to server and try the download again.     #could add a recursion ctr if suspect client ddos by dataserver
                        metadata["key"] = new_key
                        metadata["ptr"] = new_ptr

                        # Encrypt and sign file metadata
                        """ hybrid encryption start "'"
                        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, util.ObjectToBytes(metadata))
                        """
                        ephemeral, iv = crypto.SecureRandom(16), crypto.SecureRandom(16)
                        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, ephemeral) + crypto.SymmetricEncrypt(
                            ephemeral, iv, util.ObjectToBytes(metadata))
                        """ hybrid encryption  end  """
                        metadata_signature = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey),
                                                                  encrypted_metadata)

                        # Store the file in a memloc and save location to user's root structure
                        file_bytes = util.ObjectToBytes([encrypted_metadata, metadata_signature])
                        dataserver.Set(
                            crypto.HashKDF(self.root_key, filename),
                            file_bytes
                        )

                        dataserver.Delete(ptr)

                        _return = self.download_file(filename)
                        data_parts=[None]  # escape-the-return hack
                        return _return
                else:
                    data_parts.append(crypto.SymmetricDecrypt(
                        key,
                        dataserver_Get_ptr_  # cache get to prevent race condition vulnerability
                    ))

                i = i + 1
                ptr = int.to_bytes(i, 16, 'little')
        finally:
            if len(data_parts) == 0:  # or maybe 1
                # raise util.DropboxError("Failed to decrypt file data.")
                raise util.DropboxError("Failed to decrypt file data.\nFile access was revoked (either legitimately or maliciously).")  # TDO: we can edit this to distinguish between those two cases

        data = b""#data = None
        try:
            header, parts = data_parts[0], data_parts[1:]
            assert(len(header) == 16)
            parts_count = int.from_bytes(header, 'little')
            assert(len(parts) == parts_count)
            # data = b""
            for ctr, part in enumerate(parts, 1):#enumerate(data_parts)[1:]
                idx, part_data = int.from_bytes(part[:16], 'little'), part[16:]
                assert(idx == ctr)  # enforce original intended ordering
                data = data + part_data
        except AssertionError:
            raise util.DropboxError("Failed to verify file integrity.")

        return data

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/append-file.html
        """

        try:
            encrypted_metadata, metadata_signature = (None, None)
            try:
                encrypted_metadata, metadata_signature = util.BytesToObject(
                    dataserver.Get(
                        crypto.HashKDF(self.root_key, filename),
                    )
                )
            finally:
                if not all([encrypted_metadata, metadata_signature]):
                    # raise util.DropboxError("Deserialization failed.  File may have been tampered with!")
                    # raise util.DropboxError("File doesn't exist or was tampered with!")
                    raise util.DropboxError("No such file exists.")

            valid = crypto.SignatureVerify(
                crypto.SignatureVerifyKey(self.pk.libPubKey),
                encrypted_metadata,
                metadata_signature
            )
            if not valid:
                raise util.DropboxError("Metadata integrity violation")

            metadata = None
            try:
                """ hybrid decryption start "'"
                metadata = util.BytesToObject(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata
                    )
                )
                """
                metadata = util.BytesToObject(
                    crypto.SymmetricDecrypt(
                        crypto.AsymmetricDecrypt(
                            self.sk,
                            encrypted_metadata[:2048//8]
                        ),  encrypted_metadata[2048//8:]
                    )
                )
                """ hybrid decryption  end  """

                assert(metadata["filename"] == filename)  # protect against a moved-metadata attack
            finally:
                if not metadata:
                    raise util.DropboxError("Failed to decrypt metadata.")

            def isSet(ptr):
                try:
                    dataserver.Get(ptr)
                    return True
                except ValueError:
                    return False

            # Retrieve the file header (containing the parts count) and no more.
            parts_count = None
            try:
                ptr = metadata["ptr"]
                key = metadata["key"]

                dataserver_Get_ptr_ = dataserver.Get(ptr)
                valid = (
                    crypto.HMAC(key, dataserver_Get_ptr_) ==
                    dataserver.Get(ptr[-1:] + ptr[:-1])  # data_signature
                )
                if not valid:
                    raise util.DropboxError("Failed to verify file integrity.")
                else:
                    parts_count = int.from_bytes(
                        crypto.SymmetricDecrypt(  # decrypt header
                            key,
                            dataserver_Get_ptr_  # cache get to prevent race condition vulnerability
                        ), 'little'
                    )
            finally:
                if not parts_count:
                    raise util.DropboxError("Failed to decrypt file data.")
        except:
            raise util.DropboxError("Could not open file for appending or file does not exist.")

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
            encrypted_metadata, metadata_signature = (None, None)
            try:
                encrypted_metadata, metadata_signature = util.BytesToObject(
                    dataserver.Get(
                        crypto.HashKDF(self.root_key, filename),
                    )
                )
            finally:
                if not all([encrypted_metadata, metadata_signature]):
                    raise util.DropboxError("Deserialization failed.  File may have been tampered with!")

            valid = crypto.SignatureVerify(
                crypto.SignatureVerifyKey(self.pk.libPubKey),
                encrypted_metadata,
                metadata_signature
            )
            if not valid:
                raise util.DropboxError("Metadata integrity violation")

            try:
                """ hybrid decryption start "'"
                metadata = util.BytesToObject(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata
                    )
                )
                """
                metadata = util.BytesToObject(
                    crypto.SymmetricDecrypt(
                        crypto.AsymmetricDecrypt(
                            self.sk,
                            encrypted_metadata[:2048 // 8]
                        ), encrypted_metadata[2048 // 8:]
                    )
                )
                """ hybrid decryption  end  """

                assert (metadata["filename"] == filename)  # protect against a moved-metadata attack
            finally:
                if not metadata:
                    raise util.DropboxError("Failed to decrypt metadata.")
        except util.DropboxError:
            raise util.DropboxError("Failed to open file locally.")
            # raise util.DropboxError("Failed to first open the file locally.")


        metadata["share_tree"][recipient] = True


        # Encrypt and sign file metadata for owner
        """ hybrid encryption start "'"
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, util.ObjectToBytes(metadata))
        """
        ephemeral, iv = crypto.SecureRandom(16), crypto.SecureRandom(16)
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, ephemeral) + crypto.SymmetricEncrypt(ephemeral, iv, util.ObjectToBytes(metadata))
        """ hybrid encryption  end  """
        metadata_signature = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey), encrypted_metadata)

        # Store the file in a memloc and save location to user's root structure
        file_bytes = util.ObjectToBytes([encrypted_metadata, metadata_signature])
        dataserver.Set(
            crypto.HashKDF(self.root_key, filename),
            file_bytes
        )

        # Encrypt and sign file metadata for recipient
        """ hybrid encryption start "'"
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, util.ObjectToBytes(metadata))
        """
        ephemeral, iv = crypto.SecureRandom(16), crypto.SecureRandom(16)
        encrypted_metadata = crypto.AsymmetricEncrypt(recipient_pk, ephemeral) + crypto.SymmetricEncrypt(ephemeral, iv, util.ObjectToBytes(metadata))
        """ hybrid encryption  end  """
        metadata_signature = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey), encrypted_metadata)

        # Store the file in a memloc and save location to recipient's root structure
        file_bytes = util.ObjectToBytes([encrypted_metadata, metadata_signature])
        dataserver.Set(
            crypto.HashKDF(crypto.Hash(self.username.encode()+recipient.encode()), filename)[:16],
            file_bytes
        )

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

        metadata = None
        try:
            encrypted_metadata, metadata_signature = (None, None)
            try:
                encrypted_metadata, metadata_signature = util.BytesToObject(
                    dataserver.Get(
                        crypto.HashKDF(crypto.Hash(sender.encode()+self.username.encode()), filename)[:16],
                    )
                )
            finally:
                if not all([encrypted_metadata, metadata_signature]):
                    raise util.DropboxError("Deserialization failed.  File may have been tampered with!")

            valid = crypto.SignatureVerify(
                crypto.SignatureVerifyKey(sender_pk.libPubKey),
                encrypted_metadata,
                metadata_signature
            )
            if not valid:
                raise util.DropboxError("Metadata integrity violation")

            try:
                """ hybrid decryption start "'"
                metadata = util.BytesToObject(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata
                    )
                )
                """
                metadata = util.BytesToObject(
                    crypto.SymmetricDecrypt(
                        crypto.AsymmetricDecrypt(
                            self.sk,
                            encrypted_metadata[:2048//8]
                        ), encrypted_metadata[2048//8:]
                    )
                )
                """ hybrid decryption  end  """

                assert (metadata["filename"] == filename)  # protect against a moved-metadata attack
            finally:
                if not metadata:
                    raise util.DropboxError("Failed to decrypt metadata.")
        except util.DropboxError:
            raise util.DropboxError("Failed to open file locally.")
            # raise util.DropboxError("Failed to first open the file locally.")


        # metadata["share_tree"][sendefr] = True
        metadata["owner"] = sender


        # Encrypt and sign file metadata
        """ hybrid encryption start "'"
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, util.ObjectToBytes(metadata))
        """
        ephemeral, iv = crypto.SecureRandom(16), crypto.SecureRandom(16)
        encrypted_metadata = crypto.AsymmetricEncrypt(self.pk, ephemeral) + crypto.SymmetricEncrypt(ephemeral, iv, util.ObjectToBytes(metadata))
        """ hybrid encryption  end  """
        metadata_signature = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey), encrypted_metadata)

        # Store the file in a memloc and save location to user's root structure
        file_bytes = util.ObjectToBytes([encrypted_metadata, metadata_signature])
        dataserver.Set(
            crypto.HashKDF(self.root_key, filename),
            file_bytes
        )

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/revoke-file.html
        """

        recipient_pk = None
        try:
            recipient_pk = keyserver.Get(old_recipient)
        finally:
            if not recipient_pk:
                raise util.DropboxError("No such old recipient exists!")
        del recipient_pk

        metadata = None
        try:
            encrypted_metadata, metadata_signature = (None, None)
            try:
                encrypted_metadata, metadata_signature = util.BytesToObject(
                    dataserver.Get(
                        crypto.HashKDF(self.root_key, filename),
                    )
                )
            finally:
                if not all([encrypted_metadata, metadata_signature]):
                    raise util.DropboxError("Deserialization failed.  File may have been tampered with!")

            valid = crypto.SignatureVerify(
                crypto.SignatureVerifyKey(self.pk.libPubKey),
                encrypted_metadata,
                metadata_signature
            )
            if not valid:
                raise util.DropboxError("Metadata integrity violation")

            try:
                """ hybrid decryption start "'"
                metadata = util.BytesToObject(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata
                    )
                )
                """
                metadata = util.BytesToObject(
                    crypto.SymmetricDecrypt(
                        crypto.AsymmetricDecrypt(
                            self.sk,
                            encrypted_metadata[:2048 // 8]
                        ), encrypted_metadata[2048 // 8:]
                    )
                )
                """ hybrid decryption  end  """

                assert (metadata["filename"] == filename)  # protect against a moved-metadata attack
            finally:
                if not metadata:
                    raise util.DropboxError("Failed to decrypt metadata.")
        except util.DropboxError:
            raise util.DropboxError("Failed to retrieve file's share tree.")


        metadata["share_tree"][old_recipient] = False
        share_tree = metadata["share_tree"]

        old_ptr = metadata["ptr"]

        data = self.download_file(filename)
        # self.upload_file(filename, b"file " + filename.encode() + b" has been deleted")
        #delete_file
        dataserver.Delete(crypto.HashKDF(self.root_key, filename))
        dataserver.Delete(old_ptr)  # technically redundant, so could clean up a lot of code if we need to
        #maybe also delete file contents/body
        # print("deleted old file")
        self.upload_file(filename, data)  # (re)upload with a different key


        metadata = None
        try:
            encrypted_metadata, metadata_signature = (None, None)
            try:
                encrypted_metadata, metadata_signature = util.BytesToObject(
                    dataserver.Get(
                        crypto.HashKDF(self.root_key, filename),
                    )
                )
            finally:
                if not all([encrypted_metadata, metadata_signature]):
                    raise util.DropboxError("Deserialization failed.  File may have been tampered with!")

            valid = crypto.SignatureVerify(
                crypto.SignatureVerifyKey(self.pk.libPubKey),
                encrypted_metadata,
                metadata_signature
            )
            if not valid:
                raise util.DropboxError("Metadata integrity violation")

            try:
                """ hybrid decryption start "'"
                metadata = util.BytesToObject(
                    crypto.AsymmetricDecrypt(
                        self.sk,
                        encrypted_metadata
                    )
                )
                """
                metadata = util.BytesToObject(
                    crypto.SymmetricDecrypt(
                        crypto.AsymmetricDecrypt(
                            self.sk,
                            encrypted_metadata[:2048 // 8]
                        ), encrypted_metadata[2048 // 8:]
                    )
                )
                """ hybrid decryption  end  """

                assert (metadata["filename"] == filename)  # protect against a moved-metadata attack
            finally:
                if not metadata:
                    raise util.DropboxError("Failed to decrypt metadata.")
        except util.DropboxError:
            raise util.DropboxError("Failed to retrieve file's new metadata.")


        new_key = metadata["key"]
        new_ptr = metadata["ptr"]


        for user in filter(lambda e: share_tree[e], share_tree):
            # self.share_file()

            user_pk = None
            try:
                user_pk = keyserver.Get(user)
            finally:
                if not user_pk:
                    raise util.DropboxError("No such recipient exists!")
                else:
                    # Encrypt and sign file metadata
                    encrypted_new_key = crypto.AsymmetricEncrypt(user_pk, new_key+new_ptr)
                    new_key_signature = crypto.SignatureSign(crypto.SignatureSignKey(self.sk.libPrivKey), encrypted_new_key)

                    # Store the file in a memloc and save location to user's root structure
                    new_key_signed = util.ObjectToBytes([encrypted_new_key, new_key_signature])
                    dataserver.Set(old_ptr, new_key_signed)

    @classmethod
    def write(cls, ptr, data, k, sk):  # symmetric key, k, and asymmetric secret (signing) key, sk
        dataserver.Set(ptr,
           crypto.SymmetricEncrypt(
               k,
               crypto.SecureRandom(16),
               data
           )
        )  # set root
        dataserver.Set(ptr[-1:]+ptr[:-1],
            crypto.SignatureSign(
                crypto.SignatureSignKey(sk.libPrivKey),
                dataserver.Get(ptr),
            )
        )  # sign root

    @classmethod
    def read(cls, ptr, k, pk):
        data_opt = None
        try:
            data_opt =\
            crypto.SymmetricDecrypt(
                k,
                dataserver.Get(ptr)
            )
            #util.BytesToObject(
            #)
        except:
            raise util.DropboxError("Invalid password!")

        sig = dataserver.Get(ptr[-1:]+ptr[:-1])
        valid = crypto.SignatureVerify(crypto.SignatureVerifyKey(pk.libPubKey), dataserver.Get(ptr), sig)
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
    except ValueError("IdentifierAlreadyTaken"):
        raise util.DropboxError("That username is not available!")

    salt = username.encode("ascii") + b"super secret academy salt"
    root_ptr = crypto.PasswordKDF("usrdir", salt, 16)
    root_key = crypto.PasswordKDF(password, salt, 16)

    User.write(root_ptr, bytes(sk), root_key, sk)

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

    sk_bytes = User.read(root_ptr, root_key, pk)
    sk = crypto.AsymmetricDecryptKey.from_bytes(sk_bytes)

    return User(username, root_key, pk, sk)
