/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <libgen.h>

#include "fio.h"
#include "verify.h"
#include "trim.h"
#include "lib/rand.h"
#include "lib/hweight.h"
#include "lib/pattern.h"

#include "crc/md5.h"
#include "crc/crc64.h"
#include "crc/crc32.h"
#include "crc/crc32c.h"
#include "crc/crc16.h"
#include "crc/crc7.h"
#include "crc/sha256.h"
#include "crc/sha512.h"
#include "crc/sha1.h"
#include "crc/xxhash.h"
#include "crc/sha3.h"

static void populate_hdr(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_num,
			 unsigned int header_len);
static void fill_hdr(struct thread_data *td, struct io_u *io_u,
		     struct verify_header *hdr, unsigned int header_num,
		     unsigned int header_len, uint64_t rand_seed);
static void __fill_hdr(struct thread_data *td, struct io_u *io_u,
		       struct verify_header *hdr, unsigned int header_num,
		       unsigned int header_len, uint64_t rand_seed);

void fill_buffer_pattern(struct thread_data *td, void *p, unsigned int len)
{
	(void)cpy_pattern(td->o.buffer_pattern, td->o.buffer_pattern_bytes, p, len);
}

static void __fill_buffer(struct thread_options *o, unsigned long seed, void *p,
			  unsigned int len)
{
	__fill_random_buf_percentage(seed, p, o->compress_percentage, len, len, o->buffer_pattern, o->buffer_pattern_bytes);
}

static unsigned long fill_buffer(struct thread_data *td, void *p,
				 unsigned int len)
{
	struct frand_state *fs = &td->verify_state;
	struct thread_options *o = &td->o;

	return fill_random_buf_percentage(fs, p, o->compress_percentage, len, len, o->buffer_pattern, o->buffer_pattern_bytes);
}

void fill_verify_pattern(struct thread_data *td, void *p, unsigned int len,
			 struct io_u *io_u, unsigned long seed, int use_seed)
{
	struct thread_options *o = &td->o;

	if (!o->verify_pattern_bytes) {
		dprint(FD_VERIFY, "fill random bytes len=%u\n", len);

		if (use_seed)
			__fill_buffer(o, seed, p, len);
		else
			io_u->rand_seed = fill_buffer(td, p, len);
		return;
	}

	/* Skip if we were here and we do not need to patch pattern
	 * with format */
	if (!td->o.verify_fmt_sz && io_u->buf_filled_len >= len) {
		dprint(FD_VERIFY, "using already filled verify pattern b=%d len=%u\n",
			o->verify_pattern_bytes, len);
		return;
	}

	(void)paste_format(td->o.verify_pattern, td->o.verify_pattern_bytes,
			   td->o.verify_fmt, td->o.verify_fmt_sz,
			   p, len, io_u);
	io_u->buf_filled_len = len;
}

static unsigned int get_hdr_inc(struct thread_data *td, struct io_u *io_u)
{
	unsigned int hdr_inc;

	hdr_inc = io_u->buflen;
	if (td->o.verify_interval && td->o.verify_interval <= io_u->buflen)
		hdr_inc = td->o.verify_interval;

	return hdr_inc;
}

static void fill_pattern_headers(struct thread_data *td, struct io_u *io_u,
				 unsigned long seed, int use_seed)
{
	unsigned int hdr_inc, header_num;
	struct verify_header *hdr;
	void *p = io_u->buf;

	fill_verify_pattern(td, p, io_u->buflen, io_u, seed, use_seed);

	hdr_inc = get_hdr_inc(td, io_u);
	header_num = 0;
	for (; p < io_u->buf + io_u->buflen; p += hdr_inc) {
		hdr = p;
		populate_hdr(td, io_u, hdr, header_num, hdr_inc);
		header_num++;
	}
}

static void memswp(void *buf1, void *buf2, unsigned int len)
{
	char swap[200];

	assert(len <= sizeof(swap));

	memcpy(&swap, buf1, len);
	memcpy(buf1, buf2, len);
	memcpy(buf2, &swap, len);
}

static void hexdump(void *buffer, int len)
{
	uint32_t *p = buffer;
	int i;

	if (len == 1) log_err("%02x", *p & 0xff);
	if (len == 2) log_err("%04x", *p & 0xffff);
	if (len == 3) log_err("%06x", *p & 0xffffff);
	if (len >= 4) {
		assert(!(len % 4));
		for (i = 0; i < len/4; i++)
			log_err("%08x ", p[i]);
	}
	log_err("\n");
}

/*
 * Prepare for separation of verify_header and checksum header
 */
static inline unsigned int __hdr_size(int verify_type)
{
	unsigned int len = 0;

	switch (verify_type) {
	case VERIFY_NONE:
	case VERIFY_HDR_ONLY:
	case VERIFY_NULL:
	case VERIFY_PATTERN:
		len = 0;
		break;
	case VERIFY_MD5:
		len = sizeof(struct vhdr_md5);
		break;
	case VERIFY_CRC64:
		len = sizeof(struct vhdr_crc64);
		break;
	case VERIFY_CRC32C:
	case VERIFY_CRC32:
	case VERIFY_CRC32C_INTEL:
		len = sizeof(struct vhdr_crc32);
		break;
	case VERIFY_CRC16:
		len = sizeof(struct vhdr_crc16);
		break;
	case VERIFY_CRC7:
		len = sizeof(struct vhdr_crc7);
		break;
	case VERIFY_SHA256:
		len = sizeof(struct vhdr_sha256);
		break;
	case VERIFY_SHA512:
		len = sizeof(struct vhdr_sha512);
		break;
	case VERIFY_SHA3_224:
		len = sizeof(struct vhdr_sha3_224);
		break;
	case VERIFY_SHA3_256:
		len = sizeof(struct vhdr_sha3_256);
		break;
	case VERIFY_SHA3_384:
		len = sizeof(struct vhdr_sha3_384);
		break;
	case VERIFY_SHA3_512:
		len = sizeof(struct vhdr_sha3_512);
		break;
	case VERIFY_XXHASH:
		len = sizeof(struct vhdr_xxhash);
		break;
	case VERIFY_SHA1:
		len = sizeof(struct vhdr_sha1);
		break;
	case VERIFY_PATTERN_NO_HDR:
		return 0;
	default:
		log_err("fio: unknown verify header!\n");
		assert(0);
	}

	return len + sizeof(struct verify_header);
}

static inline unsigned int hdr_size(struct thread_data *td,
				    struct verify_header *hdr)
{
	if (td->o.verify == VERIFY_PATTERN_NO_HDR)
		return 0;

	return __hdr_size(hdr->verify_type);
}

static void *hdr_priv(struct verify_header *hdr)
{
	void *priv = hdr;

	return priv + sizeof(struct verify_header);
}

/*
 * Verify container, pass info to verify handlers and allow them to
 * pass info back in case of error
 */
struct vcont {
	/*
	 * Input
	 */
	struct io_u *io_u;
	unsigned int hdr_num;
	unsigned int hdr_inc;
	void *hdr;
	struct thread_data *td;

	/*
	 * Output, only valid in case of error
	 */
	const char *name;
	void *good_crc;
	void *bad_crc;
	unsigned int crc_len;
};

#define DUMP_BUF_SZ	255
static int dump_buf_warned;

static void dump_buf(char *buf, unsigned int len, unsigned long long offset,
		     const char *type, struct fio_file *f)
{
	char *ptr, fname[DUMP_BUF_SZ];
	size_t buf_left = DUMP_BUF_SZ;
	int ret, fd;

	ptr = strdup(f->file_name);

	memset(fname, 0, sizeof(fname));
	if (aux_path)
		sprintf(fname, "%s%s", aux_path, FIO_OS_PATH_SEPARATOR);

	strncpy(fname + strlen(fname), basename(ptr), buf_left - 1);

	buf_left -= strlen(fname);
	if (buf_left <= 0) {
		if (!dump_buf_warned) {
			log_err("fio: verify failure dump buffer too small\n");
			dump_buf_warned = 1;
		}
		free(ptr);
		return;
	}

	snprintf(fname + strlen(fname), buf_left, ".%llu.%s", offset, type);

	fd = open(fname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		perror("open verify buf file");
		return;
	}

	while (len) {
		ret = write(fd, buf, len);
		if (!ret)
			break;
		else if (ret < 0) {
			perror("write verify buf file");
			break;
		}
		len -= ret;
		buf += ret;
	}

	close(fd);
	log_err("       %s data dumped as %s\n", type, fname);
	free(ptr);
}

static void __dump_complete_buffer(struct thread_data *td, struct io_u *io_u)
{
	if (td->o.verify_interval && (td->o.verify_interval < io_u->buflen)) {
		/*
		 * Dump the entire buffer we just read off disk
		 */
		dump_buf(io_u->buf, io_u->buflen, io_u->offset,
				 "complete", io_u->file);
	}
}

/*
 * Dump the contents of the read block and re-generate the correct data
 * and dump that too.
 */
static void __dump_verify_buffers(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct io_u *io_u = vc->io_u;
	unsigned long hdr_offset;
	struct io_u dummy;
	void *buf;

	if (!td->o.verify_dump)
		return;

	/*
	 * Dump the contents we just read off disk
	 */
	hdr_offset = vc->hdr_num * hdr->len;

	dump_buf(io_u->buf + hdr_offset, hdr->len, io_u->offset + hdr_offset,
			"received", vc->io_u->file);

	/*
	 * Allocate a new buf and re-generate the original data
	 */
	buf = malloc(io_u->buflen);
	dummy = *io_u;
	dummy.buf = buf;
	dummy.rand_seed = hdr->rand_seed;
	dummy.start_time.tv_sec = hdr->time_sec;
	dummy.start_time.tv_usec = hdr->time_usec;
	dummy.numberio = hdr->numberio;
	dummy.buf_filled_len = 0;
	dummy.buflen = io_u->buflen;

	fill_pattern_headers(td, &dummy, hdr->rand_seed, 1);

	dump_buf(buf + hdr_offset, hdr->len, io_u->offset + hdr_offset,
			"expected", vc->io_u->file);
	free(buf);

	/*
	 * Finally dump complete read buffer
	 */
	__dump_complete_buffer(td, io_u);

}

static void dump_verify_buffers(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct verify_header shdr;

	if (td->o.verify == VERIFY_PATTERN_NO_HDR) {
		__fill_hdr(td, vc->io_u, &shdr, 0, vc->io_u->buflen, 0);
		hdr = &shdr;
	}

	__dump_verify_buffers(hdr, vc);
}

static void dump_received_buffer(struct thread_data *td, struct io_u *io_u,
				struct verify_header *hdr,unsigned int hdr_num,
				unsigned int hdr_len)
{
	unsigned long hdr_offset;

	if (!td->o.verify_dump)
		return;

	/*
	 * Dump the contents of corrupt chunk just read off disk
	 */
	hdr_offset = hdr_num * hdr->len;
	dump_buf(io_u->buf + hdr_offset, hdr_len, io_u->offset + hdr_offset,
			"received", io_u->file);

	__dump_complete_buffer(td, io_u);
}

static void log_verify_failure(struct verify_header *hdr, struct vcont *vc)
{
	unsigned long long offset;

	offset = vc->io_u->offset;
	offset += vc->hdr_num * hdr->len;
	log_err("%.8s: verify failed at file %s offset %llu, length %u\n",
			vc->name, vc->io_u->file->file_name, offset, hdr->len);

	if (vc->good_crc && vc->bad_crc) {
		log_err("       Expected CRC: ");
		hexdump(vc->good_crc, vc->crc_len);
		log_err("       Received CRC: ");
		hexdump(vc->bad_crc, vc->crc_len);
	}

	dump_verify_buffers(hdr, vc);
}

const char tracker_version_label[]   = "Fio-tracking-log-version:";
const char tracker_filename_label[]  = "DataFileName:";
const char tracker_size_label[]	  	 = "DataFileSize:";
const char tracker_offset_label[]	 = "DataFileOffset:";
const char tracker_interval_label[]  = "DataFileVerifyInterval:";
const char tracker_timestamp_label[] = "TrackingLogSaveTimestamp:";
const char tracker_checksum_label[]  = "TrackingLogChecksum:";
const char tracker_checksums_label[] = "VerifyIntervalChecksums:";

unsigned int tracker_log_version = 1;

// Retrieve the tracking array index for this verify_interval block
// We only track from starting offset of I/O range so subtract file_offset.
uint64_t get_tracking_index(struct thread_data *td, struct io_u *io_u,
			 uint64_t offset, unsigned int hdr_inc)
{
	struct fio_file *f = io_u->file;
	uint64_t index;

	index = (offset - f->file_offset) / hdr_inc;
	if (index > f->tracking_max) {
		log_err("fio: exceeded tracking array max index: %"PRIu64", max: %d, offset: %"PRIu64", inc: %d, file: %s\n",
			index, f->tracking_max, offset, hdr_inc, f->file_name);
		assert(0);
	}
	return index;
}

// Retrieve the tracking array entry for this verify_interval block
uint32_t get_tracking_entry(struct thread_data *td, struct io_u *io_u,
			 unsigned int hdr_num, unsigned int hdr_inc)
{
	struct fio_file *f = io_u->file;
	uint64_t index, block_offset;
	block_offset = io_u->offset + (hdr_num * hdr_inc);
	index = get_tracking_index(td, io_u, block_offset, hdr_inc);
	return f->tracking_array[index];
}

/*
 * Save sum of the two checksums in tracking array to detect block
 * reverting to an earlier version.
 */
static void save_tracking(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_inc)
{
	struct fio_file *f = io_u->file;
	uint32_t *data_checksum = (void *)hdr + sizeof(struct verify_header);
	uint32_t index;

	index = get_tracking_index(td, io_u, hdr->offset, header_inc);

	/* Combine header checksum plus the first 32 bits of the
	   data checksum and set Bit0 to indicate array entry exists */
	f->tracking_array[index] = (hdr->crc32 + *data_checksum) | TRACKING_EXISTS;
	/* Track changes to the tracking array in this case for a write:
	   "AW" for write I/O adding tracking checksum to array and first value
	   is file offset to the verify_interval block within this buffer,
	   u=microseconds when block written, t=tracking checksum,
	   h=header checksum, d=data checksum */
	dprint(FD_CHKSUM, "AW:%"PRIu64" u:%d t:%08x h:%08x d:%08x\n",
		hdr->offset, ((hdr->time_sec * 1000000) + hdr->time_usec),
		f->tracking_array[index], hdr->crc32, *data_checksum);
}

/*
 * Save trimmed state in tracking array. Either don't have a buffer or
 * buffer is all zeros so need separate save routine.
 */
static void save_tracking_trimmed(struct thread_data *td, struct io_u *io_u,
			 unsigned int header_num, unsigned int header_inc)
{
	struct fio_file *f = io_u->file;
	uint32_t index;
	uint64_t offset;

	offset = (uint64_t)io_u->offset + (header_num * header_inc);
	index = get_tracking_index(td, io_u, offset, header_inc);
	f->tracking_array[index] = TRACKING_TRIMMED;
	/* Track changes to the tracking array in this case for a trim:
	   "AT" for trim I/O adding a new tracking checksum to array and
	   first value is file offset to the verify_interval block within this buffer,
	   u=microseconds when block trimmed, t=tracking checksum */
	dprint(FD_CHKSUM, "AT:%"PRIu64" u:%lu t:%08x\n",
		offset, ((io_u->start_time.tv_sec * 1000000) + io_u->start_time.tv_usec),
		f->tracking_array[index]);
}

/*
 * Verify sum of the two checksums in tracking array to detect block
 * reverting to an earlier version.
 */
int _verify_tracking(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int hdr_num,
			 unsigned int hdr_inc)
{
	struct fio_file *f = io_u->file;
	uint32_t *data_checksum = (void *)hdr + sizeof(struct verify_header);
	uint32_t found;
	uint64_t index;
	const char * op;
	const char * VR = "VR";
	const char * VW = "VW";
	const char * AR = "AR";

	index = get_tracking_index(td, io_u, hdr->offset, hdr_inc);

	/* If version checksum exists then it must match or wrong version
	 * of block has been returned. */
	found = (hdr->crc32 + *data_checksum) | TRACKING_EXISTS;
	if (entry_is_checksum(f->tracking_array[index]) ) {
		if (f->tracking_array[index] != found) {
			log_err("tracking: version verify failed at file %s offset %llu, length %u\n",
				f->file_name,
				io_u->offset + hdr_num * hdr_inc, hdr_inc);
			log_err("       Expected Tracking CRC: %08x\n", f->tracking_array[index]);
			log_err("       Received Tracking CRC: %08x\n", found);
			dump_received_buffer(td, io_u, hdr, hdr_num, hdr_inc);
			if (td->o.verify_track_log) {
				log_err("To discard tracking checksum expectations on restart, first delete: %s\n", f->tracking_log_name);
			}
			return EILSEQ;
		} else {
			op = VR;
			if (is_write_verify) op = VW;
		}
	} else {
		f->tracking_array[index] = found;
		op = AR;
	}
	/* Report checksum tracking array activity. First token defined as:
	   "AR" for read I/O adding a new tracking checksum to array
	   "VR" for read that verifies against pre-existing array checksum
	   "VW" for write verify read that verifies against pre-existing array checksum.
	   First Value is file offset to the verify_interval block within this buffer,
	   u=microseconds when block written or verified based on first 2 bytes,
	   t=tracking checksum, h=header checksum, d=data checksum */
	dprint(FD_CHKSUM, "%s:%"PRIu64" u:%d t:%08x h:%08x d:%08x\n",
		op, hdr->offset, ((hdr->time_sec * 1000000) + hdr->time_usec),
		f->tracking_array[index], hdr->crc32,  *data_checksum);
	return 0;
}

// Trims needs to update tracking array indicating space no longer exists
void populate_verify_io_u_trim(struct thread_data *td, struct io_u *io_u)
{
	unsigned int hdr_inc, hdr_num = 0;
	void *p;

	if (td->o.verify == VERIFY_NULL)
		return;
	assert(io_u->ddir == DDIR_TRIM);

	if (td->o.verify_track) {
		hdr_inc = get_hdr_inc(td, io_u);
		for (p = io_u->buf; p < io_u->buf + io_u->buflen;
			p += hdr_inc, hdr_num++) {
			save_tracking_trimmed(td, io_u, hdr_num, hdr_inc);
		}
	}
}

// Restore tracking array from tracking log
int restore_tracking_array(struct thread_data *td, struct fio_file *f) {

	const char suffix[] = ".tracking.log";
	char default_dir[] = ".";
	char file_name[PATH_MAX];
	char *str_file_name = file_name;
	FILE *file;
	int max_rec = 256, r, reads, ret = 0;
	char *dir, *base, *p;
	unsigned int version, file_interval;
	uint64_t file_size, file_offset;
	uint32_t checksum, crc;
	char str_buf[max_rec];
	char *str = str_buf;
	char label_buf[max_rec+16];
	char *label = label_buf;
	char timestamp[64];
	char *str_timestamp = timestamp;

	if (!td->o.verify_track_log) {
		f->tracking_log_name = NULL;
		return 0;
	}
	// Construct tracking log filename
	if (td->o.verify_track_dir != NULL) {
		dir = td->o.verify_track_dir;
	} else {
		// If block device or pipe then default to current default directory
		// else default to directory where data file exists
		if (f->filetype != FIO_TYPE_FILE)
			dir = default_dir;
		else
			dir = dirname(f->file_name);
	}
	base = basename(f->file_name);
	if (snprintf(file_name, PATH_MAX, "%s/%s%s", dir, base, suffix) >= PATH_MAX) {
		log_err("fio: tracking log file name exceeds max of %d chars, log name: %s/%s%s truncated to %s\n",
			PATH_MAX, dir, base, suffix, file_name);
		ret = 1;
		goto err2;
	}
	f->tracking_log_name = strdup(file_name);

	// Create/Open file and read contents
	if ((file = fopen(f->tracking_log_name, "r")) == NULL) {
		// If tracking log required to be present then return error
		if (td->o.verify_track_required) {
			log_err("Tracking log '%s' missing for job '%s' for file '%s''\n",
				f->tracking_log_name, td->o.name, f->file_name);
			ret = 1;
			goto err2;
		}
		if ((file = fopen(f->tracking_log_name, "w+")) == NULL) {
			log_err("fio: failed create of Tracking Log: %s\n", f->tracking_log_name);
			perror("fio: create Tracking Log failed");
			ret = errno;
			goto err1;
		}
		// Return success on successful create
		goto success;
	}

	// Let's read the tracking log just opened
	// First record contains version and second record contains the tracking log checksum
	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing version record in header for log: %s\n", f->tracking_log_name);
		ret = errno;
		goto err;
	}
	r = sscanf(p, "%256s %u", label, &version);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log version record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_version_label)) {
		log_err("fio: bad tracking log version label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_version_label);
		ret = 1;
		goto err;
	}
	if (version != tracker_log_version) {
		log_err("fio: bad tracking log version: file '%s' has %d, expected: %d\n",
			f->tracking_log_name, version, tracker_log_version);
		ret = 1;
		goto err;
	}

	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing filename record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s %s", label, str_file_name);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log filename header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_filename_label)) {
		log_err("fio: bad tracking log filename label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_filename_label);
		ret = 1;
		goto err;
	}

	// Ideally real_file_size would be used to track the relationship between log and
	// datafile but that can be quite large for a disk block device, resulting in
	// a potentially huge array and log for a huge block device. Instead we track
	// offset= and size= options and if either change the log is incompatible and
	// we return an error.
	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing file size record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s %"PRIu64"", label, &file_size);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log file size header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_size_label)) {
		log_err("fio: bad tracking log file size label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_size_label);
		ret = 1;
		goto err;
	}
	if (file_size != f->io_size) {
		log_err("fio: bad tracking log file Size: file '%s' has %"PRIu64", running job uses: %"PRIu64"\n",
			f->tracking_log_name, file_size, f->io_size);
		ret = 1;
		goto err;
	}

	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing file offset record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s %"PRIu64"", label, &file_offset);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log file offset header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_offset_label)) {
		log_err("fio: bad tracking log file offset label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_size_label);
		ret = 1;
		goto err;
	}
	if (file_offset != f->file_offset) {
		log_err("fio: bad tracking log file Offset: file '%s' has %"PRIu64", running job uses: %"PRIu64"\n",
			f->tracking_log_name, file_offset, f->file_offset);
		ret = 1;
		goto err;
	}

	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing interval record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s %u", label, &file_interval);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log interval header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_interval_label)) {
		log_err("fio: bad tracking log interval label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_interval_label);
		ret = 1;
		goto err;
	}
	if (file_interval != td->o.verify_interval) {
		log_err("fio: bad tracking log Interval: file '%s' has %u, running job uses: %u\n",
			f->tracking_log_name, file_interval, td->o.verify_interval);
		ret = 1;
		goto err;
	}

	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing timestamp record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s %s", label, str_timestamp);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log timestamp header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_timestamp_label)) {
		log_err("fio: bad tracking log timestamp label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_timestamp_label);
		ret = 1;
		goto err;
	}

	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing checksum record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s %x", label, &checksum);
	if (r != 2) {
		log_err("fio: wrong number of fields in tracking log checksum header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_checksum_label)) {
		log_err("fio: bad tracking log checksum label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_checksum_label);
		ret = 1;
		goto err;
	}

	if ((p = fgets(str, max_rec, file)) == NULL) {
		log_err("fio: Missing verify interval checksums record in header for log: %s\n", f->tracking_log_name);
		ret = 1;
		goto err;
	}
	r = sscanf(p, "%256s", label);
	if (r != 1) {
		log_err("fio: wrong number of fields in tracking log verify interval checksums header record: %s\n", p);
		ret = 1;
		goto err;
	}
	if (strcmp(label, tracker_checksums_label)) {
		log_err("fio: bad tracking log verify interval checksums label: file '%s' has '%s', expected: '%s'\n",
			f->tracking_log_name, label, tracker_checksums_label);
		ret = 1;
		goto err;
	}

	reads = 0;
	while ((p = fgets(str, max_rec, file)) != NULL) {

		r = sscanf(p, "%x", &crc);
		if (r != 1) {
			log_err("fio: bad tracking log checksum record: %s\n", p);
			ret = 1;
			goto err;
		}
		if (!(entry_is_checksum(crc)) && !(entry_is_undefined(crc)) && !(entry_is_trimmed(crc))) {
			log_err("fio: bad tracking log checksum: %x\n", crc);
			ret = 1;
			goto err;
		}
		f->tracking_array[reads] = crc;
		reads++;
	}

	// Tracking log must have the exact number of entries for this file and block size
	if (reads-1 != f->tracking_max) {
		log_err("fio: bad tracking log, wrong number of records: file '%s' has %u recs, header expected: %u\n",
			f->tracking_log_name, reads, f->tracking_max);
		ret = 1;
		goto err;
	}
	// Tracking log file checksum must match crc of the tracking array just read in
	crc = fio_crc32c((void *)f->tracking_array, f->tracking_max * sizeof(uint32_t));
	if (crc != checksum) {
		log_err("fio: bad tracking log, checksum wrong: file '%s' records checksum to %x, header expected: %x\n",
			f->tracking_log_name, crc, checksum);
		ret = 1;
		goto err;
	}

	// Finally close and delete the file so stale entries are never used.
	dprint(FD_CHKSUM, "Successful Restore of tracking array for job '%s' for file '%s' from '%s'\n",
		td->o.name, f->file_name, f->tracking_log_name);
success:
	fclose(file);
	unlink(f->tracking_log_name);
	return ret;
err:
	fclose(file);
err1:
	log_err("fio: No tracking array restored from tracking log: %s\n", f->tracking_log_name);
	log_err("To discard tracking checksum expectations on restart, first delete: %s\n", f->tracking_log_name);
err2:
	f->tracking_log_name = NULL;
	td_verror(td, ret,"restore_tracking_array");
	return ret;
}

// Write this file's tracking array to tracking log on disk
int verify_save_tracking_array(struct thread_data *td) {

	struct fio_file *f = NULL;
	unsigned int i = 0;
	FILE *file = NULL;
	uint32_t crc;
	int ret = 0;
	char timestamp[64];
	struct timeval tv;

	for_each_file(td, f, i) {
		// Verify tracking array exists
		if (f->tracking_array == NULL) {
			log_err("fio: No tracking array exists to save for file: %s\n", f->file_name);
			ret = 1;
			goto no_close1;
		}

		if (f->tracking_log_name == NULL) continue;

		if ((file = fopen(f->tracking_log_name, "w")) == NULL) {
			perror("fio: failed to open Tracking Log");
			ret = errno;
			goto no_close;
		}

		// Tracking log header: 1) version rec 2) checksum rec 3) file size rec 4) verify interval rec
		// Finally write tracking array of checksums to tracking log file
		crc = fio_crc32c((void *)f->tracking_array, f->tracking_max * sizeof(uint32_t));

		if (fprintf(file, "%s %u\n", tracker_version_label, tracker_log_version) < 0) {
			perror("fio: failed to write version header record to tracking log");
			ret = errno;
			goto err;
		}
		if (fprintf(file, "%s %s\n", tracker_filename_label, f->file_name) < 0) {
			perror("fio: failed to write filename header record to tracking log");
			ret = errno;
			goto err;
		}
		if (fprintf(file, "%s %"PRIu64"\n", tracker_size_label, f->io_size) < 0) {
			perror("fio: failed to write file size header record to tracking log");
			ret = errno;
			goto err;
		}
		if (fprintf(file, "%s %"PRIu64"\n", tracker_offset_label, f->file_offset) < 0) {
			perror("fio: failed to write file offset header record to tracking log");
			ret = errno;
			goto err;
		}
		if (fprintf(file, "%s %u\n", tracker_interval_label, td->o.verify_interval) < 0) {
			perror("fio: failed to write interval header record to tracking log");
			ret = errno;
			goto err;
		}
		gettimeofday(&tv, NULL);
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec));
		if (fprintf(file, "%s %s.%06lu\n", tracker_timestamp_label, timestamp, (long int)tv.tv_usec) < 0) {
			perror("fio: failed to write timestamp header record to tracking log");
			ret = errno;
			goto err;
		}
		if (fprintf(file, "%s %x\n", tracker_checksum_label, crc) < 0) {
			perror("fio: failed to write checksum header record to tracking log");
			ret = errno;
			goto err;
		}
		if (fprintf(file, "%s\n", tracker_checksums_label) < 0) {
			perror("fio: failed to write verify interval checksums header record to tracking log");
			ret = errno;
			goto err;
		}

		for (int i = 0; i <= f->tracking_max; i++) {
			if (fprintf(file, "%x\n", f->tracking_array[i]) < 0) {
				perror("fio: failed to write checksum record to tracking log");
				ret = errno;
				goto err;
			}
		}
		fclose(file);
		memset(f->tracking_array, 0, f->tracking_max * sizeof(uint32_t));
		dprint(FD_CHKSUM, "Successful Save of tracking array for file '%s' to %s\n",
			f->file_name, f->tracking_log_name);
		continue;
	err:
		fclose(file);
		unlink(f->tracking_log_name);
	no_close:
		log_err("fio: failed to save tracking log for file '%s' to %s\n", f->file_name, f->tracking_log_name);
	no_close1:
		td_verror(td, ret,"verify_save_tracking_array");
		return ret;
	}
	return ret;
}

/*
 * Allocate tracking array enough to accommodate all verify_interval blocks
 */
int verify_allocate_tracking(struct thread_data *td) {
	struct fio_file *f = NULL;
	unsigned int i = 0, block_size;
	uint64_t num_entries, bytes;
	int ret = 0;

	// verify_track only works if there is one I/O outstanding against a block at a time.
	// verify_backlog performs write verification inline and thus there may be multiple
	// I/Os outstanding against the same block. While the verifying read must wait for the
	// preceding write to complete, once the verifying read queues, another write can come
	// along on that block changing the expected checksum. If the read complete before
	// the write the read contents can reflect the prior write's header. With verify_backlog
	// disabled, a close and open of the file separates verifying reads from any new writes.
	// write verification reads occurs at the end of each pass. Note this is not a concern
	// if io_depth=1. Similarly randommap is required which guarantees single accessor
	// of each block when random access is used. Like wise verify_aync is not supported
	// with verify_track, nor can you set numjobs > 1.
	//
	if (td->o.verify_backlog && (td->o.iodepth > 1)) {
		log_err("fio: verify_backlog not supported with verify_track when io_depth > 1\n");
		return 1;
	}
	if (td->o.norandommap) {
		log_err("fio: verify_track requires use of randommap which is disabled\n");
		return 1;
	}
	if (td->o.softrandommap) {
		log_err("fio: softrandommap not supported with verify_track\n");
		return 1;
	}
	if (td->o.verify_async) {
		log_err("fio: verify_async not supported with verify_track\n");
		return 1;
	}
	if (td->o.numjobs > 1) {
		log_err("fio: numjobs not supported with verify_track\n");
		return 1;
	}

	// Its required that file size be an even multiple of block size when iodepth > 1 to guarantee
	// the file is closed/flushed before verification in backend.c:do_io. Otherwise the randommap will
	// automatically wrap and we can again have multiple accessors of a block.
	block_size = td_min_bs(td);
	if ((td->o.size % block_size) && (td->o.iodepth > 1)) {
		log_err(
			"fio: verify_track requires file to be even multiple of min block size, suggested size: %llu bytes\n",
			(td->o.size / block_size) * block_size);
		log_err("fio: file size: %llu, min block size: %d\n", td->o.size, block_size);
		return 1;
	}
	// lfsr random generator does not guarantee single accessor when multiple blocks sizes are used.
	if ((td->o.random_generator == FIO_RAND_GEN_LFSR) && (td_min_bs(td) != td_max_bs(td))) {
		log_err("fio: lfsr random generator not supported with verify_track and multiple block sizes\n");
		return 1;
	}

	// File sharing by threads within a fio job is supported but not between jobs running concurrently.
	// If not the first thread then --stonewall option must be selected.
	if ((td->thread_number > 1) && (!td->o.stonewall)) {
		log_err("fio: file sharing between concurrent fio jobs is unsupported with verify_track, "
				"every job after the first job should use --stonewall\n");
		return 1;
	}
	// If trims are present then hard wire verify_track_trim_zero to true.
	if (td_trim(td)) {
		td->o.verify_track_trim_zero = 1;
	}
	// Tracking requires that a header be present which is not the case for VERIFY_PATTERN_NO_HDR.
	// In this case verification checks all bytes of a block so checksums are not really needed.
	// However tracking change over time without a header would be useful and could be added in future.
	if (td->o.verify == VERIFY_PATTERN_NO_HDR) {
		log_err("fio: verify=pattern is not supported with verify_track\n");
		return 1;
	}
	// verify=null skips updates to the tracking array and is thus not supported
	if (td->o.verify == VERIFY_NULL) {
		log_err("fio: verify=null is not supported with verify_track\n");
		return 1;
	}
	// verify_only is not supported, checksum is better version control than good numberio
	// Support is hard as assert guaranteeing write/trim entry exists in verify_io_u fire.
	// Fixable but not worth the complication.
	if (td->o.verify_only) {
		log_err("fio: verify_only is not supported with verify_track\n");
		return 1;
	}
	// Offline I/O submit mode doesn't track when finished with a pass of the file and
	// perform verification after a file close in backend.c:do_io() so not supported.
	if (td->o.io_submit_mode != IO_MODE_INLINE) {
		log_err("fio: submit_mode must be 'inline' with verify_track\n");
		return 1;
	}
	// Using a sequence number modifier on the rw option risks concurrent I/O.
	if (td->o.ddir_seq_add) {
		log_err("fio: Using sequencer number with the rw option is not supported with verify_track\n");
		return 1;
	}
	// experimental_verify not supported with verify_track
	if (td->o.experimental_verify) {
		log_err("fio: experimental_verify not supported with verify_track\n");
		return 1;
	}

	for_each_file(td, f, i) {

		if (f->tracking_array == NULL) {
			num_entries = ((f->io_size / td->o.verify_interval) + 1);
			bytes = num_entries * sizeof(uint32_t);
			f->tracking_array = malloc(bytes);
			if (!f->tracking_array) {
				log_err("fio: cannot allocate verify tracking table of size: %"PRIu64" bytes for file: %s\n",
					bytes, f->file_name);
				return 1;
			}
			memset(f->tracking_array, TRACKING_UNDEFINED, bytes);
			f->tracking_max = num_entries - 1;
			if ((ret = restore_tracking_array(td, f))) return ret;
		}
	}
	return 0;
}

/*
 * Return data area 'header_num'
 */
static inline void *io_u_verify_off(struct verify_header *hdr, struct vcont *vc)
{
	return vc->io_u->buf + vc->hdr_num * hdr->len + hdr_size(vc->td, hdr);
}

static int verify_io_u_pattern(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct io_u *io_u = vc->io_u;
	char *buf, *pattern;
	unsigned int header_size = __hdr_size(td->o.verify);
	unsigned int len, mod, i, pattern_size;
	int rc;

	pattern = td->o.verify_pattern;
	pattern_size = td->o.verify_pattern_bytes;
	assert(pattern_size != 0);

	(void)paste_format_inplace(pattern, pattern_size,
				   td->o.verify_fmt, td->o.verify_fmt_sz, io_u);

	buf = (void *) hdr + header_size;
	len = get_hdr_inc(td, io_u) - header_size;
	mod = (get_hdr_inc(td, io_u) * vc->hdr_num + header_size) % pattern_size;

	rc = cmp_pattern(pattern, pattern_size, mod, buf, len);
	if (!rc)
		return 0;

	/* Slow path, compare each byte */
	for (i = 0; i < len; i++) {
		if (buf[i] != pattern[mod]) {
			unsigned int bits;

			bits = hweight8(buf[i] ^ pattern[mod]);
			log_err("fio: got pattern '%02x', wanted '%02x'. Bad bits %d\n",
				(unsigned char)buf[i],
				(unsigned char)pattern[mod],
				bits);
			log_err("fio: bad pattern block offset %u\n", i);
			vc->name = "pattern";
			log_verify_failure(hdr, vc);
			return EILSEQ;
		}
		mod++;
		if (mod == td->o.verify_pattern_bytes)
			mod = 0;
	}

	/* Unreachable line */
	assert(0);
	return EILSEQ;
}

static int verify_io_u_xxhash(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_xxhash *vh = hdr_priv(hdr);
	uint32_t hash;
	void *state;

	dprint(FD_VERIFY, "xxhash verify io_u %p, len %u\n", vc->io_u, hdr->len);

	state = XXH32_init(1);
	XXH32_update(state, p, hdr->len - hdr_size(vc->td, hdr));
	hash = XXH32_digest(state);

	if (vh->hash == hash)
		return 0;

	vc->name = "xxhash";
	vc->good_crc = &vh->hash;
	vc->bad_crc = &hash;
	vc->crc_len = sizeof(hash);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha3(struct verify_header *hdr, struct vcont *vc,
			    struct fio_sha3_ctx *sha3_ctx, uint8_t *sha,
			    unsigned int sha_size, const char *name)
{
	void *p = io_u_verify_off(hdr, vc);

	dprint(FD_VERIFY, "%s verify io_u %p, len %u\n", name, vc->io_u, hdr->len);

	fio_sha3_update(sha3_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha3_final(sha3_ctx);

	if (!memcmp(sha, sha3_ctx->sha, sha_size))
		return 0;

	vc->name = name;
	vc->good_crc = sha;
	vc->bad_crc = sha3_ctx->sha;
	vc->crc_len = sha_size;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha3_224(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_224 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_224_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_224_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_224_DIGEST_SIZE, "sha3-224");
}

static int verify_io_u_sha3_256(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_256 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_256_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_256_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_256_DIGEST_SIZE, "sha3-256");
}

static int verify_io_u_sha3_384(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_384 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_384_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_384_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_384_DIGEST_SIZE, "sha3-384");
}

static int verify_io_u_sha3_512(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_512 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_512_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_512_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_512_DIGEST_SIZE, "sha3-512");
}

static int verify_io_u_sha512(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	uint8_t sha512[128];
	struct fio_sha512_ctx sha512_ctx = {
		.buf = sha512,
	};

	dprint(FD_VERIFY, "sha512 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_sha512_init(&sha512_ctx);
	fio_sha512_update(&sha512_ctx, p, hdr->len - hdr_size(vc->td, hdr));

	if (!memcmp(vh->sha512, sha512_ctx.buf, sizeof(sha512)))
		return 0;

	vc->name = "sha512";
	vc->good_crc = vh->sha512;
	vc->bad_crc = sha512_ctx.buf;
	vc->crc_len = sizeof(vh->sha512);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha256(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	uint8_t sha256[64];
	struct fio_sha256_ctx sha256_ctx = {
		.buf = sha256,
	};

	dprint(FD_VERIFY, "sha256 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_sha256_init(&sha256_ctx);
	fio_sha256_update(&sha256_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha256_final(&sha256_ctx);

	if (!memcmp(vh->sha256, sha256_ctx.buf, sizeof(sha256)))
		return 0;

	vc->name = "sha256";
	vc->good_crc = vh->sha256;
	vc->bad_crc = sha256_ctx.buf;
	vc->crc_len = sizeof(vh->sha256);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha1(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_sha1 *vh = hdr_priv(hdr);
	uint32_t sha1[5];
	struct fio_sha1_ctx sha1_ctx = {
		.H = sha1,
	};

	dprint(FD_VERIFY, "sha1 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_sha1_init(&sha1_ctx);
	fio_sha1_update(&sha1_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha1_final(&sha1_ctx);

	if (!memcmp(vh->sha1, sha1_ctx.H, sizeof(sha1)))
		return 0;

	vc->name = "sha1";
	vc->good_crc = vh->sha1;
	vc->bad_crc = sha1_ctx.H;
	vc->crc_len = sizeof(vh->sha1);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc7(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc7 *vh = hdr_priv(hdr);
	unsigned char c;

	dprint(FD_VERIFY, "crc7 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc7(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc7)
		return 0;

	vc->name = "crc7";
	vc->good_crc = &vh->crc7;
	vc->bad_crc = &c;
	vc->crc_len = 1;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc16(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc16 *vh = hdr_priv(hdr);
	unsigned short c;

	dprint(FD_VERIFY, "crc16 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc16(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc16)
		return 0;

	vc->name = "crc16";
	vc->good_crc = &vh->crc16;
	vc->bad_crc = &c;
	vc->crc_len = 2;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc64(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc64 *vh = hdr_priv(hdr);
	unsigned long long c;

	dprint(FD_VERIFY, "crc64 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc64(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc64)
		return 0;

	vc->name = "crc64";
	vc->good_crc = &vh->crc64;
	vc->bad_crc = &c;
	vc->crc_len = 8;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc32(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	dprint(FD_VERIFY, "crc32 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc32(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc32)
		return 0;

	vc->name = "crc32";
	vc->good_crc = &vh->crc32;
	vc->bad_crc = &c;
	vc->crc_len = 4;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc32c(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	dprint(FD_VERIFY, "crc32c verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc32c(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc32)
		return 0;

	vc->name = "crc32c";
	vc->good_crc = &vh->crc32;
	vc->bad_crc = &c;
	vc->crc_len = 4;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_md5(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_md5 *vh = hdr_priv(hdr);
	uint32_t hash[MD5_HASH_WORDS];
	struct fio_md5_ctx md5_ctx = {
		.hash = hash,
	};

	dprint(FD_VERIFY, "md5 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_md5_init(&md5_ctx);
	fio_md5_update(&md5_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_md5_final(&md5_ctx);

	if (!memcmp(vh->md5_digest, md5_ctx.hash, sizeof(hash)))
		return 0;

	vc->name = "md5";
	vc->good_crc = vh->md5_digest;
	vc->bad_crc = md5_ctx.hash;
	vc->crc_len = sizeof(hash);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

/*
 * Push IO verification to a separate thread
 */
int verify_io_u_async(struct thread_data *td, struct io_u **io_u_ptr)
{
	struct io_u *io_u = *io_u_ptr;

	pthread_mutex_lock(&td->io_u_lock);

	if (io_u->file)
		put_file_log(td, io_u->file);

	if (io_u->flags & IO_U_F_IN_CUR_DEPTH) {
		td->cur_depth--;
		io_u_clear(td, io_u, IO_U_F_IN_CUR_DEPTH);
	}
	flist_add_tail(&io_u->verify_list, &td->verify_list);
	*io_u_ptr = NULL;
	pthread_mutex_unlock(&td->io_u_lock);

	pthread_cond_signal(&td->verify_cond);
	return 0;
}

/*
 * Thanks Rusty, for spending the time so I don't have to.
 *
 * http://rusty.ozlabs.org/?p=560
 */
static int mem_is_zero(const void *data, size_t length)
{
	const unsigned char *p = data;
	size_t len;

	/* Check first 16 bytes manually */
	for (len = 0; len < 16; len++) {
		if (!length)
			return 1;
		if (*p)
			return 0;
		p++;
		length--;
	}

	/* Now we know that's zero, memcmp with self. */
	return memcmp(data, p, length) == 0;
}

static int mem_is_zero_slow(const void *data, size_t length, size_t *offset)
{
	const unsigned char *p = data;

	*offset = 0;
	while (length) {
		if (*p)
			break;
		(*offset)++;
		length--;
		p++;
	}

	return !length;
}

static int verify_trimmed_io_u(struct thread_data *td, struct io_u *io_u)
{
	size_t offset;

	if (!td->o.trim_zero)
		return 0;

	if (mem_is_zero(io_u->buf, io_u->buflen))
		return 0;

	mem_is_zero_slow(io_u->buf, io_u->buflen, &offset);

	log_err("trim: all zeroes verify failed at file %s offset %llu, length %lu"
			", block offset %lu\n",
			io_u->file->file_name, io_u->offset, io_u->buflen,
			(unsigned long) offset);
	// Dump the entire buffer we just read off disk
	dump_buf(io_u->buf, io_u->buflen, io_u->offset, "complete", io_u->file);
	return EILSEQ;
}

//
// Verify Trimmed block
// If check_buf_only set then determine if buffer is all zeros
//						 else log corruption if buffer is not all zeros
static int verify_io_u_trimmed(struct thread_data *td, struct io_u *io_u,
							   void * buf, unsigned int buflen, int check_buf_only)
{
	size_t offset;
	int ret;

	if (mem_is_zero(buf, buflen))
		ret = 0;
	else {
		mem_is_zero_slow(buf, buflen, &offset);
		ret = EILSEQ;
	}

	if (!ret) {
		if (!check_buf_only) {
			/* Report tracking array activity in this case for a trim:
			   "VT" for trim I/O read that verifies against pre-existing array checksum
			   and first value is file offset to the block used for this buffer,
			   u=microseconds when block verified. t=constant used for trimmed blocks */
			dprint(FD_CHKSUM, "VT:%llu u:%lu t:%08x\n", io_u->offset,
				  ((io_u->start_time.tv_sec * 1000000) + io_u->start_time.tv_usec),
				  TRACKING_TRIMMED);
		}
		return 0;
	}

	if (!check_buf_only) {
		log_err("trim-zeroed: all zeroes verify failed at file %s offset %llu, length %lu"
				", block offset %lu\n",
				io_u->file->file_name, io_u->offset, io_u->buflen,
				(unsigned long) (offset));
		// * Dump the entire buffer we just read off disk
		dump_buf(io_u->buf, io_u->buflen, io_u->offset, "complete", io_u->file);
	}
	return ret;
}

static int verify_header(struct io_u *io_u, struct thread_data *td,
			 struct verify_header *hdr, unsigned int hdr_num,
			 unsigned int hdr_len)
{
	void *p = hdr;
	uint32_t crc;

	if (hdr->magic != FIO_HDR_MAGIC) {
		log_err("verify: bad magic header %x, wanted %x",
			hdr->magic, FIO_HDR_MAGIC);
		goto err;
	}
	if (hdr->len != hdr_len) {
		log_err("verify: bad header length %u, wanted %u",
			hdr->len, hdr_len);
		goto err;
	}
	if (hdr->rand_seed != io_u->rand_seed) {
		log_err("verify: bad header rand_seed %"PRIu64
			", wanted %"PRIu64,
			hdr->rand_seed, io_u->rand_seed);
		goto err;
	}
	if (hdr->offset != io_u->offset + hdr_num * td->o.verify_interval) {
		log_err("verify: bad header offset %"PRIu64
			", wanted %llu",
			hdr->offset, io_u->offset);
		goto err;
	}

	/*
	 * For read-only workloads, the program cannot be certain of the
	 * last numberio written to a block. Checking of numberio will be
	 * done only for workloads that write data. Similarly for non-verification
	 * read I/Os, if using the tracking array to check validity
	 * then skip numberio check as we have no stored numberio state.
	 * Tracking checksum supercedes numberio check in this case.
	 * For verify_only, numberio will be checked in the last iteration
	 * when the correct state of numberio, that would have been written
	 * to each block in a previous run of fio, has been reached.
	 */
	if (!td_single_ddir(td, DDIR_READ) && (td_min_bs(td) == td_max_bs(td)) &&
		!td->o.time_based && (io_u->flags & IO_U_F_VER_LIST))
		if (!td->o.verify_only || td->o.loops == 0)
			if (hdr->numberio != io_u->numberio) {
				log_err("verify: bad header numberio %"PRIu16
					", wanted %"PRIu16,
					hdr->numberio, io_u->numberio);
				goto err;
			}

	crc = fio_crc32c(p, offsetof(struct verify_header, crc32));
	if (crc != hdr->crc32) {
		log_err("verify: bad header crc %x, calculated %x",
			hdr->crc32, crc);
		goto err;
	}
	return 0;

err:
	log_err(" at file %s offset %llu, length %u\n",
		io_u->file->file_name,
		io_u->offset + hdr_num * hdr_len, hdr_len);
	dump_received_buffer(td, io_u, hdr, hdr_num, hdr_len);

	return EILSEQ;
}

// Validated expected on-disk verify format
static int validate_expected_format(struct vcont *vc)
{
	struct verify_header *hdr = vc->hdr;
	struct thread_data *td = vc->td;
	struct io_u *io_u = vc->io_u;
	int ret;
	unsigned int header_size, verify_type;


	// Now lets perform check of verify on-disk format
	// First perform any requested header swap
	header_size = __hdr_size(td->o.verify);
	if (td->o.verify_offset)
		memswp(hdr, hdr + td->o.verify_offset, header_size);

	/*
	 * Make rand_seed check pass when have verifysort or
	 * verify_backlog or tracking is on.
	 */
	if (td->o.verifysort || (td->flags & TD_F_VER_BACKLOG) ||
		td->o.verify_track)
		io_u->rand_seed = hdr->rand_seed;

	if (td->o.verify != VERIFY_PATTERN_NO_HDR) {
		ret = verify_header(io_u, td, hdr, vc->hdr_num, vc->hdr_inc);
		if (ret)
			return ret;
	}

	if (td->o.verify != VERIFY_NONE)
		verify_type = td->o.verify;
	else
		verify_type = hdr->verify_type;

		switch (verify_type) {
		case VERIFY_HDR_ONLY:
			/* Header is always verified, check if pattern is left
			 * for verification. */
			if (td->o.verify_pattern_bytes)
				ret = verify_io_u_pattern(hdr, vc);
			break;
		case VERIFY_MD5:
			ret = verify_io_u_md5(hdr, vc);
			break;
		case VERIFY_CRC64:
			ret = verify_io_u_crc64(hdr, vc);
			break;
		case VERIFY_CRC32C:
		case VERIFY_CRC32C_INTEL:
			ret = verify_io_u_crc32c(hdr, vc);
			break;
		case VERIFY_CRC32:
			ret = verify_io_u_crc32(hdr, vc);
			break;
		case VERIFY_CRC16:
			ret = verify_io_u_crc16(hdr, vc);
			break;
		case VERIFY_CRC7:
			ret = verify_io_u_crc7(hdr, vc);
			break;
		case VERIFY_SHA256:
			ret = verify_io_u_sha256(hdr, vc);
			break;
		case VERIFY_SHA512:
			ret = verify_io_u_sha512(hdr, vc);
			break;
		case VERIFY_SHA3_224:
			ret = verify_io_u_sha3_224(hdr, vc);
			break;
		case VERIFY_SHA3_256:
			ret = verify_io_u_sha3_256(hdr, vc);
			break;
		case VERIFY_SHA3_384:
			ret = verify_io_u_sha3_384(hdr, vc);
			break;
		case VERIFY_SHA3_512:
			ret = verify_io_u_sha3_512(hdr, vc);
			break;
		case VERIFY_XXHASH:
			ret = verify_io_u_xxhash(hdr, vc);
			break;
		case VERIFY_SHA1:
			ret = verify_io_u_sha1(hdr, vc);
			break;
		case VERIFY_PATTERN:
		case VERIFY_PATTERN_NO_HDR:
			ret = verify_io_u_pattern(hdr, vc);
			break;
	default:
		log_err("Bad verify type %u\n", hdr->verify_type);
		ret = EINVAL;
	}

	if (ret && verify_type != hdr->verify_type)
		log_err("fio: verify type mismatch (%u media, %u given)\n",
				hdr->verify_type, verify_type);

	if (!ret) {
		if (td->o.verify_track && (td->o.verify != VERIFY_PATTERN_NO_HDR)) {
			ret = _verify_tracking(td, io_u, hdr, vc->hdr_num, vc->hdr_inc);
		}
	}
	return ret;
}

int verify_io_u(struct thread_data *td, struct io_u **io_u_ptr)
{
	struct io_u *io_u = *io_u_ptr;
	unsigned int hdr_inc, hdr_num;
	void *p;
	int ret, defined, undefined;
	uint32_t tracking_entry;

	if (td->o.verify == VERIFY_NULL || io_u->ddir != DDIR_READ)
		return 0;
	/*
	 * If the IO engine is faking IO (like null), then just pretend
	 * we verified everything.
	 */
	if (td_ioengine_flagged(td, FIO_FAKEIO))
		return 0;

	if (io_u->flags & IO_U_F_TRIMMED) {
		ret = verify_trimmed_io_u(td, io_u);
		goto done;
	}

	hdr_inc = get_hdr_inc(td, io_u);

	// For each verify_interval block
	defined = undefined = ret = hdr_num = 0;
	for (p = io_u->buf; p < io_u->buf + io_u->buflen;
		 p += hdr_inc, hdr_num++) {
		struct vcont vc = {
			.io_u		= io_u,
			.hdr_num	= hdr_num,
			.hdr_inc	= hdr_inc,
			.hdr		= p,
			.td			= td,
		};

		if (ret && td->o.verify_fatal)
			break;

		// If tracking on, use tracking array to determine type of verification format
		if (td->o.verify_track) {
			// Get tracking array entry
			// If trim verify:
			//	 Assert if entry not trimmed state
			//	 Verify trimmed verify_interval block
			tracking_entry = get_tracking_entry(td, io_u, hdr_num, hdr_inc);
			if (is_trim_verify) {
				assert (tracking_entry == TRACKING_TRIMMED);
				ret = verify_io_u_trimmed(td, io_u, p, hdr_inc, 0);
				continue;
			// If Write verify:
			//	 Assert if entry not defined checksum
			//	 Fall through to check on-disk verify format
			} else if (is_write_verify) {
				assert (tracking_entry & TRACKING_EXISTS);
			// If Read Verify:
			//	 Assert if block's tracking entries are not all undefined or all defined (checksum/trim)
			//	 If entry == Trim:
			//		 Verify trimmed verify_interval block
			//	 If entry == undefined:
			//		 When tracking file for the first time, all verify_interval blocks must be zeroed or use on-disk
			//		 verify format.
			//		 If block is all zeroes:
			//			then if verify_track_trim_zero set then Track as good trim
			//										 	   else Fall through and treat as corruption
			//			else Fall through and check for presence of on-disk verify format
			//	 If entry == checksum:
			//		 Fall through to check on-disk verify format
			} else { // Assuming this is a read verification
				if (entry_is_trimmed(tracking_entry)) {
					assert (!undefined); // Block's tracking array entries must all be defined
					defined = 1;
					ret = verify_io_u_trimmed(td, io_u, p, hdr_inc, 0);
					continue;
				} else if (entry_is_undefined(tracking_entry)) {
					assert (!defined); // Block's tracking array entries must all be undefined
					undefined = 1;
					if (!verify_io_u_trimmed(td, io_u, p, hdr_inc, 1)) {
						// Block is all zeroes and if verify_track_trim_zero set then track as good trim
						// else fall through and treat as corruption
						if (td->o.verify_track_trim_zero) {
							save_tracking_trimmed(td, io_u, hdr_num, hdr_inc);
							continue;
						}
					}
				} else if (entry_is_checksum(tracking_entry)) {
					assert (!undefined); // Block's tracking array entries must all be defined
					defined = 1;
				} else assert(0); // Unknown tracking entry
			}
		// Else tracking not enabled so deal with trim or fall through to check on-disk verify format
		} else if (is_trim_verify) {
			assert(0); // Not possible as only verify trims if tracking is on.
			continue;
		}

		// Must have expected non-zero on-disk format
		ret = validate_expected_format(&vc);
	}

done:
	if (ret && td->o.verify_fatal)
		fio_mark_td_terminate(td);

	return ret;
}

static void fill_xxhash(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_xxhash *vh = hdr_priv(hdr);
	void *state;

	state = XXH32_init(1);
	XXH32_update(state, p, len);
	vh->hash = XXH32_digest(state);
}

static void fill_sha3(struct fio_sha3_ctx *sha3_ctx, void *p, unsigned int len)
{
	fio_sha3_update(sha3_ctx, p, len);
	fio_sha3_final(sha3_ctx);
}

static void fill_sha3_224(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_224 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_224_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha3_256(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_256 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_256_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha3_384(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_384 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_384_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha3_512(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_512 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_512_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha512(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	struct fio_sha512_ctx sha512_ctx = {
		.buf = vh->sha512,
	};

	fio_sha512_init(&sha512_ctx);
	fio_sha512_update(&sha512_ctx, p, len);
}

static void fill_sha256(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	struct fio_sha256_ctx sha256_ctx = {
		.buf = vh->sha256,
	};

	fio_sha256_init(&sha256_ctx);
	fio_sha256_update(&sha256_ctx, p, len);
	fio_sha256_final(&sha256_ctx);
}

static void fill_sha1(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha1 *vh = hdr_priv(hdr);
	struct fio_sha1_ctx sha1_ctx = {
		.H = vh->sha1,
	};

	fio_sha1_init(&sha1_ctx);
	fio_sha1_update(&sha1_ctx, p, len);
	fio_sha1_final(&sha1_ctx);
}

static void fill_crc7(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc7 *vh = hdr_priv(hdr);

	vh->crc7 = fio_crc7(p, len);
}

static void fill_crc16(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc16 *vh = hdr_priv(hdr);

	vh->crc16 = fio_crc16(p, len);
}

static void fill_crc32(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc32 *vh = hdr_priv(hdr);

	vh->crc32 = fio_crc32(p, len);
}

static void fill_crc32c(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc32 *vh = hdr_priv(hdr);

	vh->crc32 = fio_crc32c(p, len);
}

static void fill_crc64(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc64 *vh = hdr_priv(hdr);

	vh->crc64 = fio_crc64(p, len);
}

static void fill_md5(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_md5 *vh = hdr_priv(hdr);
	struct fio_md5_ctx md5_ctx = {
		.hash = (uint32_t *) vh->md5_digest,
	};

	fio_md5_init(&md5_ctx);
	fio_md5_update(&md5_ctx, p, len);
	fio_md5_final(&md5_ctx);
}

static void __fill_hdr(struct thread_data *td, struct io_u *io_u,
		       struct verify_header *hdr, unsigned int header_num,
		       unsigned int header_len, uint64_t rand_seed)
{
	void *p = hdr;

	hdr->magic = FIO_HDR_MAGIC;
	hdr->verify_type = td->o.verify;
	hdr->len = header_len;
	hdr->rand_seed = rand_seed;
	hdr->offset = io_u->offset + header_num * td->o.verify_interval;
	hdr->time_sec = io_u->start_time.tv_sec;
	hdr->time_usec = io_u->start_time.tv_usec;
	hdr->thread = td->thread_number;
	hdr->numberio = io_u->numberio;
	hdr->crc32 = fio_crc32c(p, offsetof(struct verify_header, crc32));
}


static void fill_hdr(struct thread_data *td, struct io_u *io_u,
		     struct verify_header *hdr, unsigned int header_num,
		     unsigned int header_len, uint64_t rand_seed)
{

	if (td->o.verify != VERIFY_PATTERN_NO_HDR)
		__fill_hdr(td, io_u, hdr, header_num, header_len, rand_seed);
}

static void populate_hdr(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_num,
			 unsigned int header_len)
{
	unsigned int data_len;
	void *data, *p;

	p = (void *) hdr;

	fill_hdr(td, io_u, hdr, header_num, header_len, io_u->rand_seed);

	data_len = header_len - hdr_size(td, hdr);

	data = p + hdr_size(td, hdr);
	switch (td->o.verify) {
	case VERIFY_MD5:
		dprint(FD_VERIFY, "fill md5 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_md5(hdr, data, data_len);
		break;
	case VERIFY_CRC64:
		dprint(FD_VERIFY, "fill crc64 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc64(hdr, data, data_len);
		break;
	case VERIFY_CRC32C:
	case VERIFY_CRC32C_INTEL:
		dprint(FD_VERIFY, "fill crc32c io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc32c(hdr, data, data_len);
		break;
	case VERIFY_CRC32:
		dprint(FD_VERIFY, "fill crc32 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc32(hdr, data, data_len);
		break;
	case VERIFY_CRC16:
		dprint(FD_VERIFY, "fill crc16 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc16(hdr, data, data_len);
		break;
	case VERIFY_CRC7:
		dprint(FD_VERIFY, "fill crc7 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc7(hdr, data, data_len);
		break;
	case VERIFY_SHA256:
		dprint(FD_VERIFY, "fill sha256 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha256(hdr, data, data_len);
		break;
	case VERIFY_SHA512:
		dprint(FD_VERIFY, "fill sha512 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha512(hdr, data, data_len);
		break;
	case VERIFY_SHA3_224:
		dprint(FD_VERIFY, "fill sha3-224 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_224(hdr, data, data_len);
		break;
	case VERIFY_SHA3_256:
		dprint(FD_VERIFY, "fill sha3-256 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_256(hdr, data, data_len);
		break;
	case VERIFY_SHA3_384:
		dprint(FD_VERIFY, "fill sha3-384 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_384(hdr, data, data_len);
		break;
	case VERIFY_SHA3_512:
		dprint(FD_VERIFY, "fill sha3-512 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_512(hdr, data, data_len);
		break;
	case VERIFY_XXHASH:
		dprint(FD_VERIFY, "fill xxhash io_u %p, len %u\n",
						io_u, hdr->len);
		fill_xxhash(hdr, data, data_len);
		break;
	case VERIFY_SHA1:
		dprint(FD_VERIFY, "fill sha1 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha1(hdr, data, data_len);
		break;
	case VERIFY_HDR_ONLY:
	case VERIFY_PATTERN:
	case VERIFY_PATTERN_NO_HDR:
		/* nothing to do here */
		break;
	default:
		log_err("fio: bad verify type: %d\n", td->o.verify);
		assert(0);
	}

	if (td->o.verify_track)
		save_tracking(td, io_u, hdr, header_len);

	if (td->o.verify_offset && hdr_size(td, hdr))
		memswp(p, p + td->o.verify_offset, hdr_size(td, hdr));
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * checksum of choice
 */
void populate_verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (td->o.verify == VERIFY_NULL)
		return;

	io_u->numberio = td->io_issues[io_u->ddir];

	fill_pattern_headers(td, io_u, 0, 0);
}

int get_next_verify(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo = NULL;

	/*
	 * this io_u is from a requeue, we already filled the offsets
	 */
	if (io_u->file)
		return 0;

	if (!RB_EMPTY_ROOT(&td->io_hist_tree)) {
		struct rb_node *n = rb_first(&td->io_hist_tree);

		ipo = rb_entry(n, struct io_piece, rb_node);

		/*
		 * Ensure that the associated IO has completed
		 */
		read_barrier();
		if (ipo->flags & IP_F_IN_FLIGHT)
			goto nothing;

		rb_erase(n, &td->io_hist_tree);
		assert(ipo->flags & IP_F_ONRB);
		ipo->flags &= ~IP_F_ONRB;
	} else if (!flist_empty(&td->io_hist_list)) {
		ipo = flist_first_entry(&td->io_hist_list, struct io_piece, list);

		/*
		 * Ensure that the associated IO has completed
		 */
		read_barrier();
		if (ipo->flags & IP_F_IN_FLIGHT)
			goto nothing;

		flist_del(&ipo->list);
		assert(ipo->flags & IP_F_ONLIST);
		ipo->flags &= ~IP_F_ONLIST;
	}

	if (ipo) {
		td->io_hist_len--;

		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->numberio = ipo->numberio;
		io_u->file = ipo->file;
		io_u_set(td, io_u, IO_U_F_VER_LIST);

		if (ipo->flags & IP_F_TRIMMED)
			io_u_set(td, io_u, IO_U_F_TRIMMED);
		if (ipo->flags & IP_F_TRIM_VER)
			io_u_set(td, io_u, IO_U_F_TRIM_VER);
		if (ipo->flags & IP_F_WRITE_VER)
			io_u_set(td, io_u, IO_U_F_WRITE_VER);

		if (!fio_file_open(io_u->file)) {
			int r = td_io_open_file(td, io_u->file);

			if (r) {
				dprint(FD_VERIFY, "failed file %s open\n",
						io_u->file->file_name);
				return 1;
			}
		}

		get_file(ipo->file);
		assert(fio_file_open(io_u->file));
		io_u->ddir = DDIR_READ;
		io_u->xfer_buf = io_u->buf;
		io_u->xfer_buflen = io_u->buflen;

		remove_trim_entry(td, ipo);
		free(ipo);
		dprint(FD_VERIFY, "get_next_verify: ret io_u %p\n", io_u);

		if (!td->o.verify_pattern_bytes) {
			io_u->rand_seed = __rand(&td->verify_state);
			if (sizeof(int) != sizeof(long *))
				io_u->rand_seed *= __rand(&td->verify_state);
		}
		return 0;
	}

nothing:
	dprint(FD_VERIFY, "get_next_verify: empty\n");
	return 1;
}

void fio_verify_init(struct thread_data *td)
{
	if (td->o.verify == VERIFY_CRC32C_INTEL ||
	    td->o.verify == VERIFY_CRC32C) {
		crc32c_arm64_probe();
		crc32c_intel_probe();
	}
}

static void *verify_async_thread(void *data)
{
	struct thread_data *td = data;
	struct io_u *io_u;
	int ret = 0;

	if (fio_option_is_set(&td->o, verify_cpumask) &&
	    fio_setaffinity(td->pid, td->o.verify_cpumask)) {
		log_err("fio: failed setting verify thread affinity\n");
		goto done;
	}

	do {
		FLIST_HEAD(list);

		read_barrier();
		if (td->verify_thread_exit)
			break;

		pthread_mutex_lock(&td->io_u_lock);

		while (flist_empty(&td->verify_list) &&
		       !td->verify_thread_exit) {
			ret = pthread_cond_wait(&td->verify_cond,
							&td->io_u_lock);
			if (ret) {
				pthread_mutex_unlock(&td->io_u_lock);
				break;
			}
		}

		flist_splice_init(&td->verify_list, &list);
		pthread_mutex_unlock(&td->io_u_lock);

		if (flist_empty(&list))
			continue;

		while (!flist_empty(&list)) {
			io_u = flist_first_entry(&list, struct io_u, verify_list);
			flist_del_init(&io_u->verify_list);

			io_u_set(td, io_u, IO_U_F_NO_FILE_PUT);
			ret = verify_io_u(td, &io_u);

			put_io_u(td, io_u);
			if (!ret)
				continue;
			if (td_non_fatal_error(td, ERROR_TYPE_VERIFY_BIT, ret)) {
				update_error_count(td, ret);
				td_clear_error(td);
				ret = 0;
			}
		}
	} while (!ret);

	if (ret) {
		td_verror(td, ret, "async_verify");
		if (td->o.verify_fatal)
			fio_mark_td_terminate(td);
	}

done:
	pthread_mutex_lock(&td->io_u_lock);
	td->nr_verify_threads--;
	pthread_mutex_unlock(&td->io_u_lock);

	pthread_cond_signal(&td->free_cond);
	return NULL;
}

int verify_async_init(struct thread_data *td)
{
	int i, ret;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 2 * PTHREAD_STACK_MIN);

	td->verify_thread_exit = 0;

	td->verify_threads = malloc(sizeof(pthread_t) * td->o.verify_async);
	for (i = 0; i < td->o.verify_async; i++) {
		ret = pthread_create(&td->verify_threads[i], &attr,
					verify_async_thread, td);
		if (ret) {
			log_err("fio: async verify creation failed: %s\n",
					strerror(ret));
			break;
		}
		ret = pthread_detach(td->verify_threads[i]);
		if (ret) {
			log_err("fio: async verify thread detach failed: %s\n",
					strerror(ret));
			break;
		}
		td->nr_verify_threads++;
	}

	pthread_attr_destroy(&attr);

	if (i != td->o.verify_async) {
		log_err("fio: only %d verify threads started, exiting\n", i);
		td->verify_thread_exit = 1;
		write_barrier();
		pthread_cond_broadcast(&td->verify_cond);
		return 1;
	}

	return 0;
}

void verify_async_exit(struct thread_data *td)
{
	td->verify_thread_exit = 1;
	write_barrier();
	pthread_cond_broadcast(&td->verify_cond);

	pthread_mutex_lock(&td->io_u_lock);

	while (td->nr_verify_threads)
		pthread_cond_wait(&td->free_cond, &td->io_u_lock);

	pthread_mutex_unlock(&td->io_u_lock);
	free(td->verify_threads);
	td->verify_threads = NULL;
}

int paste_blockoff(char *buf, unsigned int len, void *priv)
{
	struct io_u *io = priv;
	unsigned long long off;

	typecheck(typeof(off), io->offset);
	off = cpu_to_le64((uint64_t)io->offset);
	len = min(len, (unsigned int)sizeof(off));
	memcpy(buf, &off, len);
	return 0;
}

static int __fill_file_completions(struct thread_data *td,
				   struct thread_io_list *s,
				   struct fio_file *f, unsigned int *index)
{
	unsigned int comps;
	int i, j;

	if (!f->last_write_comp)
		return 0;

	if (td->io_blocks[DDIR_WRITE] < td->o.iodepth)
		comps = td->io_blocks[DDIR_WRITE];
	else
		comps = td->o.iodepth;

	j = f->last_write_idx - 1;
	for (i = 0; i < comps; i++) {
		if (j == -1)
			j = td->o.iodepth - 1;
		s->comps[*index].fileno = __cpu_to_le64(f->fileno);
		s->comps[*index].offset = cpu_to_le64(f->last_write_comp[j]);
		(*index)++;
		j--;
	}

	return comps;
}

static int fill_file_completions(struct thread_data *td,
				 struct thread_io_list *s, unsigned int *index)
{
	struct fio_file *f;
	unsigned int i;
	int comps = 0;

	for_each_file(td, f, i)
		comps += __fill_file_completions(td, s, f, index);

	return comps;
}

struct all_io_list *get_all_io_list(int save_mask, size_t *sz)
{
	struct all_io_list *rep;
	struct thread_data *td;
	size_t depth;
	void *next;
	int i, nr;

	compiletime_assert(sizeof(struct all_io_list) == 8, "all_io_list");

	/*
	 * Calculate reply space needed. We need one 'io_state' per thread,
	 * and the size will vary depending on depth.
	 */
	depth = 0;
	nr = 0;
	for_each_td(td, i) {
		if (save_mask != IO_LIST_ALL && (i + 1) != save_mask)
			continue;
		td->stop_io = 1;
		td->flags |= TD_F_VSTATE_SAVED;
		depth += (td->o.iodepth * td->o.nr_files);
		nr++;
	}

	if (!nr)
		return NULL;

	*sz = sizeof(*rep);
	*sz += nr * sizeof(struct thread_io_list);
	*sz += depth * sizeof(struct file_comp);
	rep = malloc(*sz);
	memset(rep, 0, *sz);

	rep->threads = cpu_to_le64((uint64_t) nr);

	next = &rep->state[0];
	for_each_td(td, i) {
		struct thread_io_list *s = next;
		unsigned int comps, index = 0;

		if (save_mask != IO_LIST_ALL && (i + 1) != save_mask)
			continue;

		comps = fill_file_completions(td, s, &index);

		s->no_comps = cpu_to_le64((uint64_t) comps);
		s->depth = cpu_to_le64((uint64_t) td->o.iodepth);
		s->nofiles = cpu_to_le64((uint64_t) td->o.nr_files);
		s->numberio = cpu_to_le64((uint64_t) td->io_issues[DDIR_WRITE]);
		s->index = cpu_to_le64((uint64_t) i);
		if (td->random_state.use64) {
			s->rand.state64.s[0] = cpu_to_le64(td->random_state.state64.s1);
			s->rand.state64.s[1] = cpu_to_le64(td->random_state.state64.s2);
			s->rand.state64.s[2] = cpu_to_le64(td->random_state.state64.s3);
			s->rand.state64.s[3] = cpu_to_le64(td->random_state.state64.s4);
			s->rand.state64.s[4] = cpu_to_le64(td->random_state.state64.s5);
			s->rand.state64.s[5] = 0;
			s->rand.use64 = cpu_to_le64((uint64_t)1);
		} else {
			s->rand.state32.s[0] = cpu_to_le32(td->random_state.state32.s1);
			s->rand.state32.s[1] = cpu_to_le32(td->random_state.state32.s2);
			s->rand.state32.s[2] = cpu_to_le32(td->random_state.state32.s3);
			s->rand.state32.s[3] = 0;
			s->rand.use64 = 0;
		}
		s->name[sizeof(s->name) - 1] = '\0';
		strncpy((char *) s->name, td->o.name, sizeof(s->name) - 1);
		next = io_list_next(s);
	}

	return rep;
}

static int open_state_file(const char *name, const char *prefix, int num,
			   int for_write)
{
	char out[PATH_MAX];
	int flags;
	int fd;

	if (for_write)
		flags = O_CREAT | O_TRUNC | O_WRONLY | O_SYNC;
	else
		flags = O_RDONLY;

	verify_state_gen_name(out, sizeof(out), name, prefix, num);

	fd = open(out, flags, 0644);
	if (fd == -1) {
		perror("fio: open state file");
		log_err("fio: state file: %s (for_write=%d)\n", out, for_write);
		return -1;
	}

	return fd;
}

static int write_thread_list_state(struct thread_io_list *s,
				   const char *prefix)
{
	struct verify_state_hdr hdr;
	uint64_t crc;
	ssize_t ret;
	int fd;

	fd = open_state_file((const char *) s->name, prefix, s->index, 1);
	if (fd == -1)
		return 1;

	crc = fio_crc32c((void *)s, thread_io_list_sz(s));

	hdr.version = cpu_to_le64((uint64_t) VSTATE_HDR_VERSION);
	hdr.size = cpu_to_le64((uint64_t) thread_io_list_sz(s));
	hdr.crc = cpu_to_le64(crc);
	ret = write(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		goto write_fail;

	ret = write(fd, s, thread_io_list_sz(s));
	if (ret != thread_io_list_sz(s)) {
write_fail:
		if (ret < 0)
			perror("fio: write state file");
		log_err("fio: failed to write state file\n");
		ret = 1;
	} else
		ret = 0;

	close(fd);
	return ret;
}

void __verify_save_state(struct all_io_list *state, const char *prefix)
{
	struct thread_io_list *s = &state->state[0];
	unsigned int i;

	for (i = 0; i < le64_to_cpu(state->threads); i++) {
		write_thread_list_state(s,  prefix);
		s = io_list_next(s);
	}
}

void verify_save_state(int mask)
{
	struct all_io_list *state;
	size_t sz;

	state = get_all_io_list(mask, &sz);
	if (state) {
		char prefix[PATH_MAX];

		if (aux_path)
			sprintf(prefix, "%s%slocal", aux_path, FIO_OS_PATH_SEPARATOR);
		else
			strcpy(prefix, "local");

		__verify_save_state(state, prefix);
		free(state);
	}
}

void verify_free_state(struct thread_data *td)
{
	if (td->vstate)
		free(td->vstate);
}

void verify_assign_state(struct thread_data *td, void *p)
{
	struct thread_io_list *s = p;
	int i;

	s->no_comps = le64_to_cpu(s->no_comps);
	s->depth = le32_to_cpu(s->depth);
	s->nofiles = le32_to_cpu(s->nofiles);
	s->numberio = le64_to_cpu(s->numberio);
	s->rand.use64 = le64_to_cpu(s->rand.use64);

	if (s->rand.use64) {
		for (i = 0; i < 6; i++)
			s->rand.state64.s[i] = le64_to_cpu(s->rand.state64.s[i]);
	} else {
		for (i = 0; i < 4; i++)
			s->rand.state32.s[i] = le32_to_cpu(s->rand.state32.s[i]);
	}

	for (i = 0; i < s->no_comps; i++) {
		s->comps[i].fileno = le64_to_cpu(s->comps[i].fileno);
		s->comps[i].offset = le64_to_cpu(s->comps[i].offset);
	}

	td->vstate = p;
}

int verify_state_hdr(struct verify_state_hdr *hdr, struct thread_io_list *s)
{
	uint64_t crc;

	hdr->version = le64_to_cpu(hdr->version);
	hdr->size = le64_to_cpu(hdr->size);
	hdr->crc = le64_to_cpu(hdr->crc);

	if (hdr->version != VSTATE_HDR_VERSION)
		return 1;

	crc = fio_crc32c((void *)s, hdr->size);
	if (crc != hdr->crc)
		return 1;

	return 0;
}

int verify_load_state(struct thread_data *td, const char *prefix)
{
	struct verify_state_hdr hdr;
	void *s = NULL;
	uint64_t crc;
	ssize_t ret;
	int fd;

	if (!td->o.verify_state)
		return 0;

	fd = open_state_file(td->o.name, prefix, td->thread_number - 1, 0);
	if (fd == -1)
		return 1;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		if (ret < 0)
			td_verror(td, errno, "read verify state hdr");
		log_err("fio: failed reading verify state header\n");
		goto err;
	}

	hdr.version = le64_to_cpu(hdr.version);
	hdr.size = le64_to_cpu(hdr.size);
	hdr.crc = le64_to_cpu(hdr.crc);

	if (hdr.version != VSTATE_HDR_VERSION) {
		log_err("fio: unsupported (%d) version in verify state header\n",
				(unsigned int) hdr.version);
		goto err;
	}

	s = malloc(hdr.size);
	ret = read(fd, s, hdr.size);
	if (ret != hdr.size) {
		if (ret < 0)
			td_verror(td, errno, "read verify state");
		log_err("fio: failed reading verity state\n");
		goto err;
	}

	crc = fio_crc32c(s, hdr.size);
	if (crc != hdr.crc) {
		log_err("fio: verify state is corrupt\n");
		goto err;
	}

	close(fd);

	verify_assign_state(td, s);
	return 0;
err:
	if (s)
		free(s);
	close(fd);
	return 1;
}

/*
 * Use the loaded verify state to know when to stop doing verification
 */
int verify_state_should_stop(struct thread_data *td, struct io_u *io_u)
{
	struct thread_io_list *s = td->vstate;
	struct fio_file *f = io_u->file;
	int i;

	if (!s || !f)
		return 0;

	/*
	 * If we're not into the window of issues - depth yet, continue. If
	 * issue is shorter than depth, do check.
	 */
	if ((td->io_blocks[DDIR_READ] < s->depth ||
	    s->numberio - td->io_blocks[DDIR_READ] > s->depth) &&
	    s->numberio > s->depth)
		return 0;

	/*
	 * We're in the window of having to check if this io was
	 * completed or not. If the IO was seen as completed, then
	 * lets verify it.
	 */
	for (i = 0; i < s->no_comps; i++) {
		if (s->comps[i].fileno != f->fileno)
			continue;
		if (io_u->offset == s->comps[i].offset)
			return 0;
	}

	/*
	 * Not found, we have to stop
	 */
	return 1;
}
