# Helpful functions that might be used / reused across the script.
import hashlib
import os
import platform
import random

def is_root() -> bool:
    """
    Checks if the user is the root user
    Returns a boolean indicating this
    """
    return os.geteuid() == 0


def is_on_linux():
   """
    Checks that the user is running a Linux based OS
    Returns a boolean indicating this
    """
   os_name = platform.system()
   return os_name == "Linux"

def get_hash(value: str) -> str:
    """
    Generates a hash for a given string value
    """
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    # Byte-ify
    md5_hash.update(value.encode('utf-8'))

    return md5_hash.hexdigest()

def get_rand_int():
    """
    Gets a random integer 
    """
    return random.randint(0, 10000)