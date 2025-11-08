# Helpful functions that might be used / reused across the script.
import os
import platform

"""
    Checks if the user is the root user
    Returns a boolean indicating this
"""
def is_root() -> bool :
    return os.geteuid() == 0

"""
Checks that the user is running a Linux based OS
Returns a boolean indicating this
"""
def is_on_linux():
   os_name = platform.system()
   return os_name == "Linux"