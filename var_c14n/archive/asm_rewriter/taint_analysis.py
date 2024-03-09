import sys, getopt
import logging, os
import pprint
import inspect
from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.architecture import Architecture, ArchitectureHook
from typing import Optional
