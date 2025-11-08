import os
from .utils import is_root, is_on_linux
import logging 


# Define central logger 
logger = logging.Logger("VPC Management Logic Logger")

"""
This creates a VPC:
"""
def create_vpc():
    # Check that the user is using a Linux-based OS
    if not is_on_linux():
        logger.error("User can only run this script on a Linux based OS")
        exit(1)
    # Check that the user is the root user
    if not is_root():
       logger.error("User must be root to create a VPC")
       exit(1)

    return 