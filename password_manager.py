import os
import pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PasswordManager:
  MAX_PASSWORD_LEN = 64

  # TODO: Still need to verify checksum
  def __init__(self, password, data = None, checksum = None):
    # dictionary stores the encrypted passwords (value) for each encrypted domain (key) 
    self.kvs = {}  
    # salt for pw manager encryption
    self.salt = os.urandom(16)
    # Create the new master password 
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = self.salt, iterations = 2000000, backend = default_backend())
    self.mpw = kdf.derive(bytes(password, 'ascii'))

    # load in previous state if the checksums are valid  
    if data is not None:
      # check the checksum value 
      # load in the data
      self.kvs = pickle.loads(bytes.fromhex(data))
      # decrypt the data

  def dump(self):
    """Computes a serialized representation of the password manager
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the password
                   manager (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    return pickle.dumps(self.kvs).hex(), ''

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
    
    self.kvs[domain] = password


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

    new_password = '0'*desired_len
    self.set(domain, new_password)

    return new_password
