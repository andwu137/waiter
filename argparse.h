#ifndef ARGPARSE_H
#define ARGPARSE_H

#include <errno.h>
#include <stdint.h>

#define argparse_loop(argc, argv_i) \
	for(int argv_i = 1; \
			argv_i < argc; \
			(argv_i)++)

#define argparse_short(fail, conv, flag, out, argc, argv, argv_i) { \
	uint64_t len = strlen(flag); \
	char *arg = argv[argv_i] + len; \
	if(strncmp(argv[argv_i], flag, len) == 0) { \
		if(*arg == 0) { \
			if(!(argv_i + 1 < argc)) { fail(flag, argc, argv, argv_i); } \
			(argv_i)++; \
			arg = argv[argv_i]; \
		} \
		if(!conv(out, arg)) { fail(flag, argc, argv, argv_i); } \
		continue; \
	} \
}

#define argparse_long(fail, conv, name, out, argc, argv, argv_i) { \
	if(strcmp(argv[argv_i], name) == 0) { \
		if(!(argv_i < argc)) { fail(name, argc, argv, argv_i); } \
		if(!conv(out, argv[argv_i + 1])) { fail(name, argc, argv, argv_i); } \
		(argv_i)++; \
		continue; \
	} \
}

#define argparse_short_long(fail, conv, flag, name, out, argc, argv, argv_i) \
	argparse_short(fail, conv, flag, out, argc, argv, argv_i) \
	argparse_long(fail, conv, name, out, argc, argv, argv_i)

#define argparse_exit_short(...) argparse_short(argparse_fail, __VA_ARGS__)
#define argparse_exit_long(...) argparse_long(argparse_fail, __VA_ARGS__)
#define argparse_exit_short_long(...) argparse_short_long(argparse_fail, __VA_ARGS__)

static inline int
argparse_conv_d(
		int *out,
		char *in)
{
	char *end_ptr;
	*out = strtod(in, &end_ptr);
	return end_ptr != NULL && errno == 0; // WARN(andrew): is that right?
}

static inline int
argparse_conv_l(
		long *out,
		char *in)
{
	char *end_ptr;
	*out = strtol(in, &end_ptr, 10);
	return end_ptr == in + strlen(in) && errno == 0; // WARN(andrew): is that right?
}

static inline int
argparse_conv_ul(
		unsigned long *out,
		char *in)
{
	char *end_ptr;
	*out = strtoul(in, &end_ptr, 10);
	return end_ptr == in + strlen(in) && errno == 0; // WARN(andrew): is that right?
}

static inline int
argparse_conv_s(
		char **out,
		char *in)
{
	*out = in;
	return 1;
}

static inline void
argparse_fail(
		char *flag,
		int,
		char **argv,
		int argv_i)
{
	fprintf(stderr, "ERROR: argparse: flag: '%s': arg: %s\n", flag, argv[argv_i]);
	exit(-1);
}

#endif // ARGPARSE_H
