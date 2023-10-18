import os
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# GLOBAL REFERENCE
# kvs: dictionary for enc(domain) => enc(pw + pad + enc(domain))
# kdf: key derivation function, may not need
# master_key: master key derived from master password
# f: Fernet class created by master_key to encrypt/decrypt data
# counter: CBC IV block counter (rand based on master pw)


class PasswordManager:
  MAX_PASSWORD_LEN = 64

  # TODO: Still need to verify checksum
  def __init__(self, password, data = None, checksum = None):
    # dictionary stores the encrypted passwords (value) for each encrypted domain (key) 
    self.kvs = {}
    # salt for pw manager encryption
    self.salt = os.urandom(16)
    # derive a new master key from the provided master password 
    self.kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000, backend = default_backend())
    self.master_key = self.kdf.derive(bytes(password, 'ascii'))
    self.f = Fernet(self.master_key)
    # create a counter that begins at an arbitrary number based on the key dervived
    # TODO: Is counter only used for rand generation of passwords? Or does it need to be used in get_hash()?
    self.counter =  

    # load in previous state if the checksums are valid  
    if data is not None:
      # hash the inputed, encrypted data to obtain its hash signature
      h = hmac.HMAC(self.master_key, hashes.SHA256())
      h.update(data)
      # confirm the checksum by comparing it to the hash signature of the data
      h.verify(checksum)
      # first, decrypt the data
      temp_data = self.f.decrypt(data)
      # next, deserialize the data
      self.kvs = pickle.loads(bytes.fromhex(temp_data))
      # confirm the pw by decrypting the data with the derived key
      self.f.decrypt(data)


  def dump(self):
    """Computes a serialized representation of the password manager
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    # serialize the password manager state data
    data = pickle.dumps(self.kvs).hex()
    # encrypt the data
    enc_data = self.f.encrypt(data)
    hash_sign = self.get_hash(enc_data)
    # return the encrypted data and its hash
    return enc_data, hash_sign


  def get(self, domain):
    """Fetches the password associated with a domain from the password
       manager.
    
    Args:
      domain (str) : the domain to fetch
    
    Returns: 
      password (str) : the password associated with the requested domain if
                       it exists and otherwise None
    """
    
    if domain in self.kvs:
      return self.kvs[domain]
    return None


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
    
    # get the encryption of the domain
    enc_dom = self.get_hash(domain)
    # encrypt pw + pad + enc(domain)
    enc_pw = 
    self.kvs[enc_dom] = enc_pw


  def remove(self, domain):
    """Removes the password for the requested domain from the password
       manager.
       
       Args:
         domain (str) : the domain to remove

       Returns:
         success (bool) : True if the domain was removed and False if the domain was
                          not found
    """
    if domain in self.kvs:
      del self.kvs[domain]
      return True

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
    if domain in self.kvs:
      raise ValueError('Domain already in database')
    if desired_len > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')

    new_password = '0' * desired_len
    self.set(domain, new_password)
    return new_password
  

  # TODO: counter use/update?? Do not think so, since not using an IV
  def get_hash(self, data):
    h = hmac.HMAC(self.master_key, hashes.SHA256())
    h.update(data)
    hash_sign = h.finalize()
    return hash_sign
