#!/usr/bin/python
"""
Script to display the contents of the header from a FIO *.received, *.expected, *.complete

Inputs:
    file - FIO binary file containing block contents
"""

#===================================================================================================
import argparse
from struct import *

verify_name_list = [
    "VERIFY_NONE - No data checksum",
    "VERIFY_HDR_ONLY - No data checksum",
    "VERIFY_MD5 - 16 Byte checksum",
    "VERIFY_CRC64 - 8 Byte checksum",
    "VERIFY_CRC32 - 4 Byte checksum",
    "VERIFY_CRC32C - 4 Byte checksum",
    "VERIFY_CRC32C_INTEL - 4 Byte checksum",
    "VERIFY_CRC16 - 2 Byte checksum",
    "VERIFY_CRC7 - 1 Byte checksum",
    "VERIFY_SHA26 - 64 Byte checksum",
    "VERIFY_SHA512 - 128 Byte checksum",
    "VERIFY_XXHASH - 4 Byte checksum",
    "VERIFY_SHA1 - 20 Byte checksum",
    "VERIFY_PATTERN - No data checksum",
    "VERIFY_PATTERN_NO_HDR - No data checksum",
    "VERIFY_NULL - No data checksum",
    ]

#===================================================================================================
def main():
    """Format FIO block header"""
    parser = argparse.ArgumentParser()
    parser.add_argument('fio_file', help='FIO binary file from a detected data corruption')

    args = parser.parse_args()
    print("\nArguments:")
    print("FIO File Containing block contents: %s\n" % args.fio_file)

    f = open(args.fio_file, "rb")
    magic = int(unpack('H', f.read(2))[0])
    verify_type = int(unpack('H', f.read(2))[0])
    verify_name = "Bad Value"
    if verify_type < len(verify_name_list):
        verify_name = verify_name_list[verify_type]
    blklen = int(unpack('I', f.read(4))[0])
    rand_seed = unpack('Q', f.read(8))
    offset = int(unpack('Q', f.read(8))[0])
    time_sec = int(unpack('I', f.read(4))[0])
    time_usec = int(unpack('I', f.read(4))[0])
    thread = int(unpack('H', f.read(2))[0])
    number_io = int(unpack('H', f.read(2))[0])
    crc32 = int(unpack('I', f.read(4))[0])
    data_chksum = int(unpack('I', f.read(4))[0])
    tracking_chksum = crc32 + data_chksum | 1

    print("BLOCK HEADER")
    print("                Magic Constant: 0x%x - %s" % (magic, ("Good" if magic == 0xacca
                                                                 else "Bad Value, magic constant 0xacca missing,"
                                                                      " all other fields suspect")))
    print("                 Data CRC Type: 0x%x (%d) - %s" % (verify_type, verify_type, verify_name))
    print("                  Block Length: 0x%x (%d)" % (blklen, blklen))
    print("                   Random Seed: 0x%x" % rand_seed)
    print("                        Offset: 0x%x (%d)" % (offset, offset))
    print("                  Time Seconds: 0x%x (%d)" % (time_sec, time_sec))
    print("             Time Microseconds: 0x%x (%d)" % (time_usec, time_usec))
    print("                 Thread Number: 0x%x (%d)" % (thread, thread))
    print("          Number of Write I/Os: 0x%x (%d)" % (number_io, number_io))
    print("        Header CRC32c Checksum: 0x%x" % crc32)
    print("First 4 Bytes of Data Checksum: 0x%x" % data_chksum)
    print("             Tracking Checksum: 0x%s" % ("%x" % tracking_chksum)[-8:])

#===================================================================================================
if __name__ == "__main__":
    main()
