#!/bin/bash
# corruption_triage.sh
# Script to perform this triage promptly when FIO corruptions occur.
# The script uses DD while still accelerated to confirm presence of any corruption in the cache and then
# after decelerating checks what exists on disk. Also provides hex translation of the binary data and
# display differences. Script assumes that a received file beginning with "sd*." is a block device and
# will prefix "/dev/" to the block device. Otherwise it assume a file system file is involved.
#
# Triage steps are, for each received file:
# 1) Shutdown all workload I/O activity promptly to preserve the corrupted cache contents.
# 2) Re-read failed blocks while accelerated with dd with for example:
#   ./corruption_triage.sh sdb.984850432.received dd_accelerated
# 3) Re-read the corrupted block directly from disk once disk has been decelerated with dd. Example:
#   ./corruption_triage.sh sdb.984850432.received dd_decelerated
# 4) Study the diffs to determine:
#   - Does FIO received data and dd_accelerated data agree? Confirms the corruption is still present in cache. Larger
#       cache have a greater likelihood of preserving the corruption.
#   - Does FIO received data and DD-decelerated data from disk agreed? Normally the disk data is the right data.
#       If data is different, determine which is the correct data by examining the block header in the first few bytes:
#           - The hex magic field must be set to 0x'acca'
#           - Verify that both blocks belong at that address, hex offset field should match decimal offset in
#               received file name.
#           - Verify that that the len field is correct for this block size which is the size of the received file.
#           - Examine the hex time_sec field which is the number of seconds since the start of the FIO run that
#               this block's contents were written. The latter value is normally the correct data.
#           - The tracking array value points to which block FIO thinks is correct. Adding the CRC fields together
#               in one of these blocks should match the tracking array value. The formula is:
#               (crc32 + datachecksum) | 1
#           - Examine the pattern of matching and not matching bytes in the block. The beginning and end points of
#               the corruption can often provide useful hints about the source of the corruption.
#   - The error message in the fio log indicates exactly what FIO found corrupt, see "verify=str" description in
#       auto/src/fio/fio-fio-2.2.10/HOWTO
#
# Here is the layout of the block header and use fio_header.py to display header contents:
#   struct verify_header {
#   	uint16_t magic;
#   	uint16_t verify_type;
#   	uint32_t len;
#   	uint64_t rand_seed;
#   	uint64_t offset;
#   	uint32_t time_sec;
#   	uint32_t time_usec;
#   	uint16_t thread;
#   	uint16_t numberio;
#   	uint32_t crc32;
#   	uint32_t datachecksum; /* first 4 bytes of data checksum
#   };
#
#
# Here's a DD trick can be used to verify the data integrity of any received or complete file whose contents
# are suspected of being intact:
#
# Do a successful run of the FIO script sending output to a file named xxx. The block size is 4096 and
# the block offset contained in the corrupted block is 8265728 and 2018 = 8265728 / 4096. Change the fio script
# to use rw=read.
#
# $ cp xxx xxx.mod
# $ dd if=fio-20170104045652.8269824.received  of=xxx.mod ibs=4k obs=4k skip=0 seek=2018 count=1 conv=nocreat,notrunc
# 1+0 records in
# 1+0 records out
# 4096 bytes (4.1 kB) copied, 0.000278434 s, 14.7 MB/s
# $ fio --filename=xxx.mod --debug=io,chksum simple.read.fio > xxx.mod.read.log
# $
#
# If this last fio run does not generate a corruption error then to confirm success, search xxx.mod.read.log
# for 8265728 to find a read to this offset and a successful checksum validation "chksum" log message.
# Verify that the correct checksum was used in the verification as the checksums displayed
# for the "chksum" log message should match the expected checksum displayed by fio_header.py.
#

function usage()
{
    echo ""
    echo "Usage: ./corruption_triage.sh <received_file_name> <dd_accelerated|dd-decelerated>"
    echo ""
    exit
}

filename=$1
action=$2
dd_accelerated="dd_accelerated"
dd_decelerated="dd_decelerated"
if [ -z $filename ]
    then
        echo "Error: received filename missing"
        usage
fi
if [ ! -f $filename ]
    then
        echo "Error: No such Received filename: $filename"
        usage
fi
if [ "$action" != "$dd_accelerated" ] && [ "$action" != "$dd_decelerated" ]
    then
        echo "Error: No such action argument: $action"
        usage
fi

# Get the offset and the blksize
blksize=`ls -l $filename | cut -f5 -d " "`
offset=`echo $filename | cut -f2 -d"."`
source_file=`echo $filename | cut -f1 -d"."`
len=${#source_file}
prefix=${source_file:0:2}

# if block device suspected then add prefix /dev/
# If using a file system don't your files with device names like "sdb"
if [ $len -eq 3 ] && [ $prefix == "sd" ]
    then
        source_file="/dev/$source_file"
fi

echo ""
echo "FIO Received File: $filename"
echo "FIO Source Data File: $source_file"
echo "Action: $action"
echo "File Offset: $offset"
echo "Block Size: $blksize"
echo ""

# Generate the DD command and fetch the data
skip=`expr $offset / $blksize`
sudo dd if=$source_file iflag=direct count=1 bs=$blksize skip=$skip of=$filename.$action

# Convert to binary to hex
cat $filename | hexdump > $filename.hex
cat $filename.$action | hexdump > $filename.$action.hex

# Display relevant differences
if [ -f $filename.$dd_accelerated.hex ]
    then
        echo ""
        echo "====> Compare FIO Received Buffer to DD data while still accelerated (No output = Identical files)"
        diff $filename.hex  $filename.$dd_accelerated.hex
fi
if [ -f $filename.$dd_decelerated.hex ]
    then
        echo ""
        echo "====> Compare FIO Received Buffer to DD data after decelerated (No output = Identical files)"
        diff $filename.hex  $filename.$dd_decelerated.hex
fi

# All done
