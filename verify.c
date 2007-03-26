/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "fio.h"
#include "os.h"

static void fill_random_bytes(struct thread_data *td,
			      unsigned char *p, unsigned int len)
{
	unsigned int todo;
	double r;

	while (len) {
		r = os_random_double(&td->verify_state);

		/*
		 * lrand48_r seems to be broken and only fill the bottom
		 * 32-bits, even on 64-bit archs with 64-bit longs
		 */
		todo = sizeof(r);
		if (todo > len)
			todo = len;

		memcpy(p, &r, todo);

		len -= todo;
		p += todo;
	}
}

static void hexdump(void *buffer, int len)
{
	unsigned char *p = buffer;
	int i;

	for (i = 0; i < len; i++)
		log_info("%02x", p[i]);
	log_info("\n");
}

static int verify_io_u_crc32(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	unsigned long c;

	p += sizeof(*hdr);
	c = crc32(p, hdr->len - sizeof(*hdr));

	if (c != hdr->crc32) {
		log_err("crc32: verify failed at %llu/%lu\n", io_u->offset, io_u->buflen);
		log_err("crc32: wanted %lx, got %lx\n", hdr->crc32, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_md5(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct md5_ctx md5_ctx;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	p += sizeof(*hdr);
	md5_update(&md5_ctx, p, hdr->len - sizeof(*hdr));

	if (memcmp(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash))) {
		log_err("md5: verify failed at %llu/%lu\n", io_u->offset, io_u->buflen);
		hexdump(hdr->md5_digest, sizeof(hdr->md5_digest));
		hexdump(md5_ctx.hash, sizeof(md5_ctx.hash));
		return 1;
	}

	return 0;
}

int verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	struct verify_header *hdr = (struct verify_header *) io_u->buf;
	int ret;

	if (td->o.verify == VERIFY_NULL)
		return 0;

	if (hdr->fio_magic != FIO_HDR_MAGIC) {
		log_err("Bad verify header %x\n", hdr->fio_magic);
		return EIO;
	}

	if (hdr->verify_type == VERIFY_MD5)
		ret = verify_io_u_md5(hdr, io_u);
	else if (hdr->verify_type == VERIFY_CRC32)
		ret = verify_io_u_crc32(hdr, io_u);
	else {
		log_err("Bad verify type %u\n", hdr->verify_type);
		ret = 1;
	}

	if (ret)
		return EIO;

	return 0;
}

static void fill_crc32(struct verify_header *hdr, void *p, unsigned int len)
{
	hdr->crc32 = crc32(p, len);
}

static void fill_md5(struct verify_header *hdr, void *p, unsigned int len)
{
	struct md5_ctx md5_ctx;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	md5_update(&md5_ctx, p, len);
	memcpy(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash));
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * crc32 or md5 sum of that data.
 */
void populate_verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct verify_header hdr;

	hdr.fio_magic = FIO_HDR_MAGIC;
	hdr.len = io_u->buflen;
	p += sizeof(hdr);
	fill_random_bytes(td, p, io_u->buflen - sizeof(hdr));

	if (td->o.verify == VERIFY_MD5) {
		fill_md5(&hdr, p, io_u->buflen - sizeof(hdr));
		hdr.verify_type = VERIFY_MD5;
	} else if (td->o.verify == VERIFY_CRC32) {
		fill_crc32(&hdr, p, io_u->buflen - sizeof(hdr));
		hdr.verify_type = VERIFY_CRC32;
	}

	memcpy(io_u->buf, &hdr, sizeof(hdr));
}

int get_next_verify(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;
	struct rb_node *n;

	/*
	 * this io_u is from a requeue, we already filled the offsets
	 */
	if (io_u->file)
		return 0;

	n = rb_first(&td->io_hist_tree);
	if (n) {
		ipo = rb_entry(n, struct io_piece, rb_node);

		rb_erase(n, &td->io_hist_tree);

		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->file = ipo->file;
		io_u->ddir = DDIR_READ;
		io_u->xfer_buf = io_u->buf;
		io_u->xfer_buflen = io_u->buflen;
		free(ipo);
		return 0;
	}

	return 1;
}
