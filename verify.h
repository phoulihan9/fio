#ifndef FIO_VERIFY_H
#define FIO_VERIFY_H

#include <stdint.h>
#include "io_ddir.h"
#include "verify-state.h"

#define FIO_HDR_MAGIC	0xacca

enum {
	VERIFY_NONE = 0,		/* no verification */
	VERIFY_HDR_ONLY,		/* verify header only, kept for sake of
					 * compatibility with old configurations
					 * which use 'verify=meta' */
	VERIFY_MD5,			/* md5 sum data blocks */
	VERIFY_CRC64,			/* crc64 sum data blocks */
	VERIFY_CRC32,			/* crc32 sum data blocks */
	VERIFY_CRC32C,			/* crc32c sum data blocks */
	VERIFY_CRC32C_INTEL,		/* crc32c sum data blocks with hw */
	VERIFY_CRC16,			/* crc16 sum data blocks */
	VERIFY_CRC7,			/* crc7 sum data blocks */
	VERIFY_SHA256,			/* sha256 sum data blocks */
	VERIFY_SHA512,			/* sha512 sum data blocks */
	VERIFY_SHA3_224,		/* sha3-224 sum data blocks */
	VERIFY_SHA3_256,		/* sha3-256 sum data blocks */
	VERIFY_SHA3_384,		/* sha3-384 sum data blocks */
	VERIFY_SHA3_512,		/* sha3-512 sum data blocks */
	VERIFY_XXHASH,			/* xxhash sum data blocks */
	VERIFY_SHA1,			/* sha1 sum data blocks */
	VERIFY_PATTERN,			/* verify specific patterns */
	VERIFY_PATTERN_NO_HDR,		/* verify specific patterns, no hdr */
	VERIFY_NULL,			/* pretend to verify */
};

/*
 * A header structure associated with each checksummed data block. It is
 * followed by a checksum specific header that contains the verification
 * data.
 */
struct verify_header {
	uint16_t magic;
	uint16_t verify_type;
	uint32_t len;
	uint64_t rand_seed;
	uint64_t offset;
	uint32_t time_sec;
	uint32_t time_usec;
	uint16_t thread;
	uint16_t numberio;
	uint32_t crc32;
};

struct vhdr_md5 {
	uint32_t md5_digest[4];
};
struct vhdr_sha3_224 {
	uint8_t sha[224 / 8];
};
struct vhdr_sha3_256 {
	uint8_t sha[256 / 8];
};
struct vhdr_sha3_384 {
	uint8_t sha[384 / 8];
};
struct vhdr_sha3_512 {
	uint8_t sha[512 / 8];
};
struct vhdr_sha512 {
	uint8_t sha512[128];
};
struct vhdr_sha256 {
	uint8_t sha256[64];
};
struct vhdr_sha1 {
	uint32_t sha1[5];
};
struct vhdr_crc64 {
	uint64_t crc64;
};
struct vhdr_crc32 {
	uint32_t crc32;
};
struct vhdr_crc16 {
	uint16_t crc16;
};
struct vhdr_crc7 {
	uint8_t crc7;
};
struct vhdr_xxhash {
	uint32_t hash;
};

/*
 * Verify helpers
 */
extern void populate_verify_io_u(struct thread_data *, struct io_u *);
extern void populate_verify_io_u_trim(struct thread_data *, struct io_u *);
extern int __must_check get_next_verify(struct thread_data *td, struct io_u *);
extern int __must_check verify_io_u(struct thread_data *, struct io_u **);
extern int verify_io_u_async(struct thread_data *, struct io_u **);
extern void fill_verify_pattern(struct thread_data *td, void *p, unsigned int len, struct io_u *io_u, unsigned long seed, int use_seed);
extern void fill_buffer_pattern(struct thread_data *td, void *p, unsigned int len);
extern void fio_verify_init(struct thread_data *td);
extern int verify_save_tracking_array(struct thread_data *);
extern int verify_allocate_tracking(struct thread_data *);

/*
 * Async verify offload
 */
extern int verify_async_init(struct thread_data *);
extern void verify_async_exit(struct thread_data *);

/*
 * Callbacks for pasting formats in the pattern buffer
 */
extern int paste_blockoff(char *buf, unsigned int len, void *priv);

/*
 * Verify only if do_verify and verify are set. Also
 * if write or trim (but not trim & write) and verify enabled and
 * not experimental verify then log the I/O for later verification.
 * Trim & write is unusual as two I/Os (trim and then write) are
 * performed serially on each block by relying on a fragile
 * handoff from the freelist so we can't safely insert a read
 * to verify the trim. The follow-on write is verified though due
 * to the first clause. Note trims can only be meaningfully verified
 * if verify_track is used otherwise fio assumes reads following
 * a trim returning a zeroed block is corruption. verify_track
 * tracks trims not followed by a write and allows reads of
 * such blocks to be zeroed.
 */
#define verify_enabled(td)    ((td)->o.do_verify && (td)->o.verify != VERIFY_NONE)
#define verifiable_ddir(td)   (verify_enabled(td) && ((td_write(td)) || _verifiable_trims(td)))
#define verifiable_writes(td) (verify_enabled(td) && td_write(td))
#define verifiable_trims(td)  (verify_enabled(td) && _verifiable_trims(td))
#define _verifiable_trims(td) (td_trim(td) && !td_trim_and_write(td) && (td)->o.verify_track)
#define verifiable_io(td, io_u)  (verify_enabled(td) && \
       (((io_u)->ddir == DDIR_WRITE) || \
        ((io_u)->ddir == DDIR_TRIM && !td_trim_and_write(td) && (td)->o.verify_track)))
#define tracking_enabled(td)  ((td->o.verify != VERIFY_NONE) && td->o.verify_track)
#define tracking_log_enabled(td)  ((td->o.verify != VERIFY_NONE) && td->o.verify_track \
                                    && td->o.verify_track_log)

#endif
