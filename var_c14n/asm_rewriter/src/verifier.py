import fileinput
import time
import os, sys
import logging
import re
import csv

# Get the same logger instance. Use __name__ to get a logger with a hierarchical name or a specific string to get the exact same logger.
logger = logging.getLogger('main')

# Add the parent directory to sys.path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from main import *

from insts import *

def is_instruction(line):
    """
    Check if a line is an assembly instruction.
    This function assumes that an assembly instruction starts with
    an alphanumeric character (excluding labels and directives) and
    not a comment or empty line.
    """
    # Trim leading and trailing whitespaces
    stripped_line = line.strip()

    # Check for empty line, comment, label, or directive
    if (not stripped_line or
        stripped_line.startswith(';') or
        ':' in stripped_line or
        stripped_line.startswith('.')):
        return False

    # Assuming the line is an instruction if it doesn't fall into the above categories
    return True

def parse_assembly_instructions(filename):
    """
    Parses the given assembly file and prints out only the assembly instructions.
    """
    instructions = []

    with open(filename, 'r') as file:
        for line in file:
            if is_instruction(line):
                instructions.append(line.strip())

    return instructions


def static_verifier(file_path, flag):
    verify_count = 0
    check = True
    if flag.PRE:
        logger.info("Pre-condition verification")
        # Example usage
        instructions = parse_assembly_instructions(file_path)
        for instruction in instructions:
            # Regex pattern to match opcodes
            pattern = r"^\s*(\b\w+\b)"
            print(instruction)
            opcodes = re.findall(pattern, instruction, re.MULTILINE)
            for opcode in opcodes:
                # Capitalize the opcode
                opcode = opcode.upper()
                # Check if the capitalized opcode exists in the Instruction enum
                # and print the result
                inst_check = IntelInstruction.has_value(opcode)
                
                if inst_check:
                    logger.critical("Checked")
                else:
                    logger.error("Verify failed %s", opcode)
                    check = False
                    # exit()
        return check