#ifndef FIO_DDIR_H
#define FIO_DDIR_H

enum fio_ddir {
	DDIR_READ = 0,
	DDIR_WRITE = 1,
	DDIR_TRIM = 2,
	DDIR_RWDIR_CNT = 3,
	DDIR_SYNC = 3,
	DDIR_DATASYNC,
	DDIR_SYNC_FILE_RANGE,
	DDIR_WAIT,
	DDIR_LAST,
	DDIR_INVAL = -1,
};

enum fio_ddir_mask {
	DDIR_READ_MASK  = 1 << DDIR_READ,
	DDIR_WRITE_MASK = 1 << DDIR_WRITE,
	DDIR_TRIM_MASK  = 1 << DDIR_TRIM,
};

static inline const char *io_ddir_name(enum fio_ddir ddir)
{
	static const char *name[] = { "read", "write", "trim", "sync",
					"datasync", "sync_file_range",
					"wait", };

	if (ddir < DDIR_LAST)
		return name[ddir];

	return "invalid";
}

enum td_ddir {
	TD_DDIR_READ			= 1 << DDIR_READ,
	TD_DDIR_WRITE			= 1 << DDIR_WRITE,
	TD_DDIR_TRIM			= 1 << DDIR_TRIM,
	TD_DDIR_RAND			= 1 << 3,
	TD_DDIR_TRIM_AND_WRITE	= 1 << 4,

	TD_DDIR_RW				= TD_DDIR_READ | TD_DDIR_WRITE,
	TD_DDIR_RANDREAD		= TD_DDIR_READ | TD_DDIR_RAND,
	TD_DDIR_RANDWRITE		= TD_DDIR_WRITE | TD_DDIR_RAND,
	TD_DDIR_RANDRW			= TD_DDIR_RW | TD_DDIR_RAND,
	TD_DDIR_RANDTRIM		= TD_DDIR_TRIM | TD_DDIR_RAND,
	TD_DDIR_TRIMWRITE		= TD_DDIR_TRIM | TD_DDIR_WRITE | TD_DDIR_TRIM_AND_WRITE,
	TD_DDIR_WRITETRIM		= TD_DDIR_WRITE | TD_DDIR_TRIM,
	TD_DDIR_RANDWRITETRIM	= TD_DDIR_WRITE | TD_DDIR_TRIM | TD_DDIR_RAND,
	TD_DDIR_READTRIM		= TD_DDIR_READ | TD_DDIR_TRIM,
	TD_DDIR_RANDREADTRIM	= TD_DDIR_READ | TD_DDIR_TRIM | TD_DDIR_RAND,
	TD_DDIR_RWT				= TD_DDIR_READ | TD_DDIR_WRITE | TD_DDIR_TRIM,
	TD_DDIR_RANDRWT			= TD_DDIR_READ | TD_DDIR_WRITE | TD_DDIR_TRIM | TD_DDIR_RAND,

};

// Return true if the workload is using this type of I/O
#define td_read(td)		((td)->o.td_ddir & TD_DDIR_READ)
#define td_write(td)	((td)->o.td_ddir & TD_DDIR_WRITE)
#define td_trim(td)		((td)->o.td_ddir & TD_DDIR_TRIM)
#define td_rw(td)		(((td)->o.td_ddir & TD_DDIR_RW) == TD_DDIR_RW)
#define td_random(td)	((td)->o.td_ddir & TD_DDIR_RAND)

// Return true if workload is exactly:
#define td_trim_and_write(td)	((td)->o.td_ddir == TD_DDIR_TRIMWRITE)
#define td_writetrim(td)		((td)->o.td_ddir == TD_DDIR_WRITETRIM)
#define td_randwritetrim(td)	((td)->o.td_ddir == TD_DDIR_RANDWRITETRIM)
#define td_readtrim(td)			((td)->o.td_ddir == TD_DDIR_READTRIM)
#define td_randreadtrim(td)		((td)->o.td_ddir == TD_DDIR_RANDREADTRIM)
#define td_rwt(td)				((td)->o.td_ddir == TD_DDIR_RWT)
#define td_randrwt(td)			((td)->o.td_ddir == TD_DDIR_RANDRWT)

// Return mask of I/O types
#define td_eligible_ddirs(td)   ((td)->o.td_ddir & TD_DDIR_RWT)
// Return true if multiple I/O type bits are set in td_ddir
#define td_multiple_ddirs(td)   (td_eligible_ddirs(td) & (td_eligible_ddirs(td) - 1))
// Return true if fio_ddir argument bit is only bit set in td_ddir
#define td_single_ddir(td, fio_ddir)  (td_eligible_ddirs(td) == (1 << (fio_ddir)))

#define file_randommap(td, f)	(!(td)->o.norandommap && fio_file_axmap((f)))

static inline int ddir_sync(enum fio_ddir ddir)
{
	return ddir == DDIR_SYNC || ddir == DDIR_DATASYNC ||
	       ddir == DDIR_SYNC_FILE_RANGE;
}

static inline int ddir_rw(enum fio_ddir ddir)
{
	return ddir == DDIR_READ || ddir == DDIR_WRITE || ddir == DDIR_TRIM;
}

static inline const char *ddir_str(enum td_ddir ddir)
{
	const char *__str[] = { NULL, "read", "write", "rw", "trim",
				"readtrim", "writetrim", "rwt", NULL,
				"randread", "randwrite", "randrw", "randtrim",
				"randreadtrim", "randwritetrim", "randrwt",
				NULL, NULL, NULL, NULL, NULL, NULL,
				"trimwrite", NULL, NULL, NULL, NULL,
				NULL, NULL, NULL, NULL, NULL};

	return __str[ddir];
}

#define ddir_rw_sum(arr)	\
	((arr)[DDIR_READ] + (arr)[DDIR_WRITE] + (arr)[DDIR_TRIM])

#endif
