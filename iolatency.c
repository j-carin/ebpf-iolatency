#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "iolatency.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })


// Resets bpf map
int reset_histogram(int hist_fd) {
    for (int i = 0; i < SLOTS; i++) {
        int zero = 0;
        if (bpf_map_update_elem(hist_fd, &i, &zero, BPF_ANY) < 0)  {
            return -1;
        }
    }

    return 0;
}

// Gets and resets histogram
int get_histogram(int hist_fd, uint32_t *userspace_hist) {
    for (int i = 0; i < SLOTS; i++) {
        // kinda bad, copy 64 bytes to 32 bytes
        uint64_t val;
        if (bpf_map_lookup_elem(hist_fd, &i, &val) < 0) {
            return -1;
        }

        userspace_hist[i] = (uint32_t) val;
    }

    return reset_histogram(hist_fd);
}

// from https://github.com/iovisor/bcc/blob/master/libbpf-tools/trace_helpers.c
static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog, *prog2, *prog3;
    struct bpf_link *link, *link2, *link3;
    int prog_fd, prog_fd2, prog_fd3;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interval>\n", argv[0]);
        return 1;
    }

    int interval = argv[1];

    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "block_rq_insert");
    prog2 = bpf_object__find_program_by_name(obj, "block_rq_issue");
    prog3 = bpf_object__find_program_by_name(obj, "block_rq_complete");
    if(libbpf_get_error(prog) || libbpf_get_error(prog2) || libbpf_get_error(prog3)) {
        fprintf(stderr, "ERROR: finding BPF program in obj file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    prog_fd2 = bpf_program__fd(prog2);
    prog_fd3 = bpf_program__fd(prog3);
    if (prog_fd < 0 || prog_fd2 < 0 || prog_fd3 < 0) {
        fprintf(stderr, "ERROR: getting file descriptor for BPF program failed\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    link2 = bpf_program__attach(prog2);
    link3 = bpf_program__attach(prog3);
    if (libbpf_get_error(link) || libbpf_get_error(link2) || libbpf_get_error(link3)) {
        fprintf(stderr, "ERROR: attaching BPF program to kprobe failed\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *latency_hist;
    latency_hist = bpf_object__find_map_by_name(obj, "latency_hist");
    if (libbpf_get_error(latency_hist)) {
        fprintf(stderr, "ERROR: finding BPF map in obj file failed\n");
        goto cleanup;
    }

    int hist_fd = bpf_map__fd(latency_hist);
    if (hist_fd < 0) {
        fprintf(stderr, "ERROR: getting file descriptor for BPF map failed\n");
        goto cleanup;
    }

    uint32_t userspace_hist[SLOTS];

    for (;;) {
        sleep(interval);

        if (get_histogram(hist_fd, userspace_hist) < 0) {
            fprintf(stderr, "ERROR: Could not get histogram\n");
            goto cleanup;
        }

        print_log2_hist(userspace_hist, SLOTS, "usecs");
    }

cleanup:
    bpf_link__destroy(link);
    bpf_link__destroy(link2);
    bpf_link__destroy(link3);
    bpf_object__close(obj);

    return 0;
}
