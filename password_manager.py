import math
import os
import pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Class used to dump pw manager state that is encrypted before dumping
class PWManagerDumpEnc:
    def __init__(self, counter, dictionary):
        self.counter = counter
        self.dictionary = dictionary


# Class that is not encrypted, contains encrypted pw manager state, and salt in plaintext
class PWManagerDumpUnenc:
    def __init__(self, salt, enc):
        self.salt = salt
        self.enc = enc


# REFERENCE
# kvs: dictionary for enc(domain) => (enc(pw + pad + enc(domain)), nonce)
# master_key: master key derived from master password using PBKDF2HMAC and salt
# f: AES-GCM function initialized with master_key to encrypt/decrypt data
# counter: Counter used in conjunction with HMAC to produce random output for enc/gen_new
# salt: salt for master_key generation from password


class PasswordManager:
    MAX_PASSWORD_LEN = 64
    PAD_PW_LEN = MAX_PASSWORD_LEN + 1

    def __init__(self, password, data=None, checksum=None):
        self.kvs = {}

        # If data is not None, then we are loading in a previous state of the password manager
        if data is not None:
            # hash the encrypted data to obtain its signature and verify with checksum
            hash = self.get_hash(data)
            if hash != checksum:
                raise ValueError("Invalid checksum")
            unencObj: PWManagerDumpUnenc = pickle.loads(data)
            self.salt = unencObj.salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=2000000,
                backend=default_backend(),
            )
            try:
                self.master_key = kdf.derive(bytes(password, "ascii"))
                self.f = AESGCM(self.master_key)
                # first, decrypt the password manager state
                temp_data_dump = self.f.decrypt(unencObj.enc[1], unencObj.enc[0], None)
            except:
                raise ValueError("Invalid password")
            else:
                try:
                    encObj: PWManagerDumpEnc = pickle.loads(temp_data_dump)
                    self.kvs = encObj.dictionary
                    self.counter = encObj.counter
                except:
                    raise ValueError("Malformed State")
        else:
            # randomly generate salt for pw manager derivation
            self.salt = os.urandom(16)
            # the new master key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=2000000,
                backend=default_backend(),
            )
            # derive master_key from password
            self.master_key = kdf.derive(bytes(password, "ascii"))
            # Authenticated encryption function (AEAD scheme)
            self.f = AESGCM(self.master_key)
            # create a counter that begins at a random number based on the key dervived and a "Nothing up my sleeve number"
            counter_init = self.get_hmac("0123456789ABCDEFFEDCBA9876543210F0E1D2C3")
            self.counter = int.from_bytes(counter_init[0:4], "big")

    def dump(self):
        """Computes a serialized representation of the password manager
           together with a checksum.

        Returns:
          data (str) : a hex-encoded serialized representation of the contents of the password
                       manager (that can be passed to the constructor)
          checksum (str) : a hex-encoded checksum for the data used to protect
                           against rollback attacks (up to 32 characters in length)
        """
        # The PW Manger state that needs to be encrypted
        dumpBeforeEnc = PWManagerDumpEnc(self.counter, self.kvs)
        # encrypt the state
        dumpAfterEnc = self.get_encrypt(
            bytes.fromhex(pickle.dumps(dumpBeforeEnc).hex())
        )
        # The state that will be pickled and returned, includes plaintext salt and encrypted data
        dumpObj = PWManagerDumpUnenc(self.salt, dumpAfterEnc)
        pickleDump = pickle.dumps(dumpObj)
        # Get checksum of the state
        hash_sign = self.get_hash(pickleDump)
        # return the dump and its checksum
        return pickleDump, hash_sign

    def get(self, domain):
        """Fetches the password associated with a domain from the password
           manager.

        Args:
          domain (str) : the domain to fetch

        Returns:
          password (str) : the password associated with the requested domain if
                           it exists and otherwise None
        """
        password = None
        # get the hmac of the domain
        hash_dom = self.get_hmac(domain)
        # determine if it is present in the dictionary of domains to passwords
        if hash_dom in self.kvs:
            value = self.kvs[hash_dom]
            # value = (enc, nonce)
            dec_value = self.f.decrypt(value[1], value[0], None)
            # Check for a swap attack by determining if the correct domain is stored in the encrypted password
            if dec_value[65:] == hash_dom:
                # first 65 characters are padded pw
                padded_pw = dec_value[:65]
                return self.remove_padding(padded_pw)
        return password

    def set(self, domain, password):
        """Associates a password with a domain and adds it to the password
        manager (or updates the associated password if the domain is already
        present in the password manager).

        Args:
          domain (str) : the domain to set
          password (str) : the password associated with the domain

        Returns:
          None

        Raises:
          ValueError : if password length exceeds the maximum
        """
        if len(password) > self.MAX_PASSWORD_LEN:
            raise ValueError("Maximum password length exceeded")
        # add padding to the password to 65 bytes
        padded_pw = self.set_padding(password)
        # get the hmac of the domain
        dom_hash = self.get_hmac(domain)
        # encrypt the padded password + encrypted domain to prevent swap attacks
        value = self.get_encrypt(padded_pw + dom_hash)
        self.kvs[dom_hash] = value

    def remove(self, domain):
        """Removes the password for the requested domain from the password
        manager.

        Args:
          domain (str) : the domain to remove

        Returns:
          success (bool) : True if the domain was removed and False if the domain was
                           not found
        """
        # get the hmac of the domain
        enc_dom = self.get_hmac(domain)
        # if domain was in the dictionary delete it and return true
        if enc_dom in self.kvs:
            del self.kvs[enc_dom]
            return True
        # domain was not the in the dictionary no entries deleted
        return False

    def generate_new(self, domain, desired_len):
        """Generates a password for a particular domain. The password
        is a random string with characters drawn from [A-Za-z0-9].
        The password is automatically added to the password manager for
        the associated domain.

        Args:
          domain (str) : the domain to generate a password for
          desired_len (int) : length of the password to generate (in characters)

        Returns:
          password (str) : the generated password

        Raises:
          ValueError : if a password already exists for the provided domain
          ValueError : if the requested password length exceeds the maximum
        """
        # get domain hmac
        domain_hash = self.get_hmac(domain)
        if domain_hash in self.kvs:
            raise ValueError("Domain already in database")
        if desired_len > self.MAX_PASSWORD_LEN:
            raise ValueError("Maximum password length exceeded")
        # HMAC is a PRF so sufficient to produce random output of 32 bytes
        num_iter = math.ceil(desired_len / 32)
        res_bytes = b""
        # chaining HMACs is equivelant to chaining PRFs to produce a PRG
        for i in range(num_iter):
            rand_sect = self.get_hmac(str(self.counter))
            res_bytes += rand_sect
            # Increment counter so each HMAC produces nondeterministic random output
            self.increment_counter()
        bytes_len = res_bytes[:desired_len]
        # Map random bytes to alphanumeric characters
        new_pw = self.bytes_to_alphanum(bytes_len)
        self.set(domain, new_pw)
        return new_pw

    # Encrypt arbitrary bytes with AES-GCM
    def get_encrypt(self, data):
        # Generate random nonce with HMAC from master_key and counter
        nonce = self.get_hmac(str(self.counter))
        self.increment_counter()
        enc = self.f.encrypt(nonce, data, None)
        return (enc, nonce)

    # HMAC string data with SHA256, equivalent to PRF
    def get_hmac(self, data):
        h = hmac.HMAC(self.master_key, hashes.SHA256())
        h.update(bytes(data, "ascii"))
        return h.finalize()

    # Increment counter value and wrap around if necessary
    def increment_counter(self):
        self.counter = self.counter + 1
        self.counter %= 2**32

    # Hash arbitrary bytes with SHA256
    def get_hash(self, data):
        h = hashes.Hash(hashes.SHA256())
        h.update(data)
        hash_sign = h.finalize()
        return hash_sign

    # map bytes to A-Z, a-z, 0-9
    def bytes_to_alphanum(self, bytes):
        res = ""
        for b in bytes:
            b %= 62
            if b < 26:
                # A = 65
                res += chr(b + 65)
            elif b < 52:
                # a=97
                res += chr(b - 26 + 97)
            else:
                # 0=48
                res += chr(b - 52 + 48)
        return res

    # Given string of length 65, remove padding and return original password
    def remove_padding(self, pw_padded):
        if len(pw_padded) != self.PAD_PW_LEN:
            raise ValueError("Bad padded length")
        # read last byte to get padding length, know always at least one
        pad_val = pw_padded[-1]
        # verify that many bytes of padding are present with that value
        for i in range(len(pw_padded) - 1, pad_val, -1):
            if pw_padded[i] != pad_val:
                raise ValueError("Bad padding")
        return pw_padded[: self.PAD_PW_LEN - pad_val].decode()

    # Given string of length <= 64, add padding with value=#padding bytes to make 65 bytes
    def set_padding(self, data):
        # always add at least one byte of padding
        diff = int.to_bytes(self.PAD_PW_LEN - len(data), 1, "big")
        result = data.ljust(self.PAD_PW_LEN, bytes.decode(diff, "ascii"))
        return bytes(result, "ascii")
