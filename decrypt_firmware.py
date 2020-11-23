#!/usr/bin/env python3
# encoding: utf-8
"""

    This script can be used to decrypt Canon MG6450 printer firmwares

    (c) 2020 Synacktiv
"""

import argparse
import logging
import logging.handlers
import sys
import os
import string
from pprint import pprint

logger = logging.getLogger(os.path.splitext(os.path.basename(sys.argv[0]))[0])


POSSIBLE_CHARS = ['\x0d', '\n', 'S'] + list(string.hexdigits)
POSSIBLE_CHARS = bytearray([ord(x) for x in POSSIBLE_CHARS])

KEYLEN = 0x10


def calculate_errors(chunks, index):
    logger.info("Trying smart bruteforce for index %d", index)

    possible_keys = {i: 0 for i in range(0, 0xFF)}

    error_chunks = []

    for key in possible_keys:
        for i, chunk in enumerate(chunks[:-1]):
            if (chunk[index] ^ key) in POSSIBLE_CHARS:
                continue

            elif chunk in error_chunks:
                continue
            elif i == 0:
                break
            possible_keys[key] += 1
            error_chunks.append((i, bytearray([mychunk[index] ^ key for mychunk in chunks])))
            break
    pprint(error_chunks)


def bruteforce_char(chunks, index):
    logger.info("Bruteforcing key for index %d", index)
    possible_keys = []
    for key in range(0, 0xFF):
        for chunk in chunks[:-1]:
            if (chunk[index] ^ key) in POSSIBLE_CHARS:
                continue
            else:
                break
        else:
            possible_keys.append(key)

    if not possible_keys:
        calculate_errors(chunks, index)
    return possible_keys


def xor_decrypt(data, key):
    out = []

    for index, char in enumerate(data):
        out.append(char ^ key[index % len(key)])

    return bytearray(out)


def dump_to_file(data, key, fname):
    logger.info("Dumping decrypted data to %s", fname)
    mkey = bytearray()

    for key_item in key:
        mkey.append(key[key_item][0])

    mdata = xor_decrypt(data, mkey)
    with open(fname, "wb") as of:
        of.write(mdata)


def decrypt(fname):

    with open(fname, "rb") as mfile:
        data = mfile.read()

    chunks = [data[i:i + KEYLEN] for i in range(0, len(data), KEYLEN)]

    logger.info("Got %d chunks", len(chunks))

    possible_keys = {}

    possible_keys[0] = [chunks[0][0] ^ ord('S')]

    for i in range(1, KEYLEN):
        possible_keys[i] = bruteforce_char(chunks[1:100000], i)
        logger.info("Got %d possible keys: %s", len(possible_keys[i]), possible_keys[i])

    for index in possible_keys:
        if len(possible_keys[index]) > 1:
            logger.info("Got too much possible keys for offset %d", index)
            possible_keys[index] = bruteforce_char(chunks[1:200000], index)
            logger.info("Got %d possible keys: %s", len(possible_keys[index]), possible_keys[index])

    # sanity check
    #for mkey in possible_keys:
    #    if len(possible_keys[mkey]) != 1:
    #        logger.error("Error, we have %d multiple key!", len(possible_keys))
    #        raise IOError

    dump_to_file(data, possible_keys, "decrypted.bin")


def setup_logging(options):
    """Configure logging."""
    root = logging.getLogger("")
    root.setLevel(logging.WARNING)
    logger.setLevel(options.debug and logging.DEBUG or logging.INFO)
    if not options.silent:
        if not sys.stderr.isatty():
            facility = logging.handlers.SysLogHandler.LOG_DAEMON
            sh = logging.handlers.SysLogHandler(address='/dev/log',
                                                facility=facility)
            sh.setFormatter(logging.Formatter(
                "{0}[{1}]: %(message)s".format(
                    logger.name,
                    os.getpid())))
            root.addHandler(sh)
        else:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter(
                "%(levelname)s[%(name)s] %(message)s"))
            root.addHandler(ch)


def main():
    """
        Argument parsing
    """
    parser = argparse.ArgumentParser(description=sys.modules[__name__].__doc__)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--debug", "-d", action="store_true",
                       default=False,
                       help="enable debugging")
    group.add_argument("--silent", "-s", action="store_true",
                       default=False,
                       help="don't log to console")

    parser.add_argument("file", help="the file to decrypt")

    args = parser.parse_args()

    setup_logging(args)
    decrypt(args.file)


if __name__ == "__main__":
    main()
