My program is run using: ./mydig websiteName A
To implement dnssec, +dnssec will be added to the command line (ie. ./mydig websiteName A +dnssec)

This means that both part A and part B of the assignment is written in the file labled mydig.py.

The imported libaries are:

from pip._vendor.distlib.compat import raw_input
import dns.query
import dns.resolver
import dns.message
import sys
import time
from datetime import datetime
import re
import copy
import matplotlib.pyplot as plt

There was an additional extension I had to install called cryptography (pip install cryptography)