import math
import os
import enum
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Class used to dump pw manager that is encrypted before dumping
class PWManagerDumpEnc:
  def __init__(self, counter, dictionary):
    self.counter = counter
    self.dictionary = dictionary

# Class that is not encrypted, contains encrypted pw manager state, and salt in pla
class PWManagerDumpUnenc:
  def __init__(self, salt, enc):
    self.salt = salt
    self.enc = enc



# GLOBAL REFERENCE
# kvs: dictionary for enc(domain) => enc(pw + pad + enc(domain))
# kdf: key derivation function, may not need
# master_key: master key derived from master password
# f: Fernet class created by master_key to encrypt/decrypt data, may not need if we can reproduce with same master key
# counter: CBC IV block counter (rand based on master pw)
# salt: salt for this pw


class PasswordManager:
  MAX_PASSWORD_LEN = 64


  def __init__(self, password, data = None, checksum = None):
    self.kvs = {}

    if data is not None:
      print("INITIALIZING FROM DUMP")
      # hash the inputed, encrypted data to obtain its hash signature
      hash = self.get_hash(data)
      if(hash != checksum):
        return False
      # read salt from data, first 16 bytes unencrypted
      unencObj:PWManagerDumpUnenc = pickle.loads(data)
      self.salt = unencObj.salt
      print("SALT: ", self.salt)
      self.kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000, backend = default_backend())
      self.master_key = self.kdf.derive(bytes(password, 'ascii'))
      self.f = AESGCM(self.master_key)
      # first, decrypt the data
      temp_data_dump = self.f.decrypt(unencObj.enc[1], unencObj.enc[0], None)
      encObj: PWManagerDumpEnc = pickle.loads(temp_data_dump)
      # next, deserialize the data
      self.kvs = encObj.dictionary
      self.counter = encObj.counter
      print("DONE INITIALIZING")
    else:
      # dictionary stores the encrypted passwords (value) for each encrypted domain (key) 
      
      # salt for pw manager encryption
      self.salt = os.urandom(16)
      # derive a new master key derivation function from the provided master password 
      # TODO: may not need as global 
      self.kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000, backend = default_backend())
      # get bytes of pw w/ pading, see post #115
      #padded_pw = self.get_padding(bytes(password, 'ascii'))
      #print('len of padded pw, ', len(padded_pw))
      # derive a new master key derivation function from the provided master password 
      self.master_key = self.kdf.derive(bytes(password, 'ascii'))
      print('len of master key, ', len(self.master_key))
      print(self.master_key)
      # TODO: function for encrypting data, might be HMAC? need to discuss
      # may not need to save as global... need to discuss
      self.f = AESGCM(self.master_key)
      # AESGCM(self.master_key).
      # create a counter that begins at an arbitrary number based on the key dervived
      # TODO: Is counter only used for rand generation of passwords? Or does it need to be used in get_hash()?
      # TODO: Is counter the nonce value?
      self.counter = 0

      # load in previous state if the checksums are valid  
    
        # parse values (counter, dictionary) from decrypted data


  def dump(self):
    """Computes a serialized representation of the password manager
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    # serialize the password manager state data: (counter + dictionary)
    dumpBeforeEnc = PWManagerDumpEnc(self.counter, self.kvs)
    # get the dictionary
    # dict = pickle.dumps(self.kvs).hex()(
    # encrypt the dictionary
    # enc_dict = self.get_encrypt(dict) # TODO: FIX ALL ENCRYPT
    # encrypt the counter
    # enc_cnt = self.get_encrypt(self.counter)
    # encrypt the master password
    # enc_mpw = self.get_encrypt(self.master_key)
    # TODO: include salt
    # encrypted data to return:= master password + counter (+ enc/dec function) + salt + dictionary
    # enc_data = enc_cnt + enc_dict
    
    dumpAfterEnc = self.get_encrypt(bytes.fromhex(pickle.dumps(dumpBeforeEnc).hex()))
    dumpObj = PWManagerDumpUnenc(self.salt, dumpAfterEnc)
    pickleDump = pickle.dumps(dumpObj)
    hash_sign = self.get_hash(pickleDump)
    # return the encrypted data and its hash
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
    # get the encryption of the domain
    hash_dom = self.get_hmac(domain)
    # print("Enc dom:", hash_dom)
    # print("Dict keys: ", self.kvs.keys())
    # determine if it is present in the dicitionary of domains to passwords
    if hash_dom in self.kvs:
      value = self.kvs[hash_dom]
      dec_value = self.f.decrypt(value[1], value[0], None)
      # Check for a swap attack, determine if the domain stored in the encrypted
      # password value is equivalent to the domain being requested in the call
      # TODO: throw warning if false?
      # print("DECRYPTED DOMAIN: ", dec_value)
      if dec_value[65:] == hash_dom:
        # TODO: scheme to unpad the padding
        padded_pw = dec_value[:65]
        print(self.remove_padding(padded_pw))
        return self.remove_padding(padded_pw)
        #password = 
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
      raise ValueError('Maximum password length exceeded')
    # add padding to the password to 64bytes
    padded_pw = self.get_padding(password)
    # get the encryption of the domain
    # enc_dom = self.get_encrypt(bytes(domain, "ascii"))
    dom_hash = self.get_hmac(domain)
    # encrypt the padded password + encrypted domain
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
    # get the encryption of the domain

    enc_dom = self.get_hmac(domain)
    # domain was in the dictionary, therefore delete it and return true
    if enc_dom in self.kvs:
      del self.kvs[enc_dom]
      return True
    # domain was not the in the dictionary, therefore no eentries deleted
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
    domain_hash = self.get_hmac(domain)
    if domain_hash in self.kvs:
      raise ValueError('Domain already in database')
    if desired_len > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')
    # HMAC is a PRF so sufficient to produce random output
    # HMAC outputs 32 bytes
    num_iter = math.ceil(desired_len/32)
    res_bytes = b""
    for i in range(num_iter):
      rand_sect = self.get_hmac(str(self.counter))
      res_bytes += rand_sect
      self.counter += 1
    bytes_len = res_bytes[:desired_len]
    print(bytes_len)
    new_pw = self.bytes_to_alphanum(bytes_len)
    self.set(domain, new_pw)
    return new_pw
  

  # TODO: HEAVILY REVIEW ENCRYPTION SCHEME and counter update
  def get_encrypt(self, data):
    nonce = self.get_hmac(str(self.counter))
    self.counter = self.counter + 1
    enc = self.f.encrypt(nonce, data, None)
    return (enc, nonce)

  def get_hmac(self, data):
    h = hmac.HMAC(self.master_key, hashes.SHA256())
    h.update(bytes(data, 'ascii'))
    return h.finalize()

  # TODO: counter use/update?? Do not think so, since not using an IV
  def get_hash(self, data):
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    hash_sign = h.finalize()
    return hash_sign
  
  # map to A-Z, a-z, 0-9
  def bytes_to_alphanum(self, bytes):
    res = ""
    for b in bytes:
      b %= 62
      # b = int.to_bytes(b, 1, 'big')
      if b < 26:
        # A = 65
        res += chr(b+65)
      elif b < 52:
        # a=97
        res += chr(b-26+97)
      else:
        # 0=48
        res += chr(b-52+48)
    return res

  def remove_padding(self, pw_padded):
    if len(pw_padded) != self.MAX_PASSWORD_LEN+1:
      raise ValueError("Bad padded length")
    # print("PW PADDED", pw_padded)
    # read last byte to get padding length, know always at least one
    pad_val = pw_padded[-1]
    # print("PAD VAL: ", pad_val)
    for i in range(len(pw_padded)-1, pad_val, -1):
      if(pw_padded[i] != pad_val):
        raise ValueError("Bad padding")
    return pw_padded[:self.MAX_PASSWORD_LEN+1-pad_val].decode()



  def get_padding(self, data):
      # always add at least one byte of padding
      pw_w_padding_len = self.MAX_PASSWORD_LEN+1
      # print("Diff: ", self.MAX_PASSWORD_LEN - len(data))
      diff = int.to_bytes(pw_w_padding_len - len(data), 1, 'big')
      result = data.ljust(pw_w_padding_len, bytes.decode(diff, "ascii"))
      #result = data.ljust(self.MAX_PASSWORD_LEN, diff)
      # print(bytes(result)) # TODO: check how we pad
      # print(result)
      return bytes(result, "ascii")
