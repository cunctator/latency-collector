// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017, 2018, 2019 BMW Car IT GmbH
 * Author: Viktor Rosendahl (viktor.rosendahl@bmw.de)
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <linux/unistd.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <pthread.h>

static const char *prg_name;
static const char *prg_unknown = "unknown program name";

static int fd_stdout;

/* These are default values */
static int sched_policy;
static bool sched_policy_set;

static int sched_pri;
static bool sched_pri_set;

static bool trace_enable = true;
static bool use_random_sleep;

static char inotify_buffer[655360];

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
#define bool2str(x)    (x ? "true":"false")

#define DEFAULT_NR_PRINTER_THREADS (3)
static unsigned int nr_threads = DEFAULT_NR_PRINTER_THREADS;

#define DEFAULT_TABLE_SIZE (2)
static unsigned int table_startsize = DEFAULT_TABLE_SIZE;

static int verbosity;

#define verbose_sizechange() (verbosity >= 1)
#define verbose_lostevent()  (verbosity >= 2)

static const char *debug_tracefile;
static const char *debug_tracefile_dflt = "/sys/kernel/debug/tracing/trace";
static const char *debug_maxlat_file;
static const char *debug_maxlat_dflt =
	"/sys/kernel/debug/tracing/tracing_max_latency";


#define DEV_URANDOM     "/dev/urandom"
#define RT_DEFAULT_PRI (99)
#define DEFAULT_PRI    (0)

#define USEC_PER_MSEC (1000L)
#define NSEC_PER_USEC (1000L)
#define NSEC_PER_MSEC (USEC_PER_MSEC * NSEC_PER_USEC)

#define MSEC_PER_SEC (1000L)
#define USEC_PER_SEC (USEC_PER_MSEC * MSEC_PER_SEC)
#define NSEC_PER_SEC (NSEC_PER_MSEC * MSEC_PER_SEC)

#define SLEEP_TIME_MS_DEFAULT (1000L)

static long sleep_time = (USEC_PER_MSEC * SLEEP_TIME_MS_DEFAULT);

static char queue_full_warning[] =
"Could not queue trace for printing. It is likely that events happen faster\n"
"than what they can be printed. Probably partly because of random sleeping\n";


struct policy {
	const char *name;
	int policy;
	int default_pri;
};

static const struct policy policies[] = {
	{ "other", SCHED_OTHER, DEFAULT_PRI    },
	{ "batch", SCHED_BATCH, DEFAULT_PRI    },
	{ "idle",  SCHED_IDLE,  DEFAULT_PRI    },
	{ "rr",    SCHED_RR,    RT_DEFAULT_PRI },
	{ "fifo",  SCHED_FIFO,  RT_DEFAULT_PRI },
	{ NULL,    0,           DEFAULT_PRI    }
};

struct entry {
	int ticket;
	int ticket_completed_ref;
};

struct print_state {
	int ticket_counter;
	int ticket_completed;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int cnt;
	pthread_mutex_t cnt_mutex;
};

struct short_msg {
	char buf[160];
	int len;
};

static struct print_state printstate;

#define PROB_TABLE_MAX_SIZE (1000)

int probabilities[PROB_TABLE_MAX_SIZE];

struct sleep_table {
	int *table;
	int size;
	pthread_mutex_t mutex;
};

static struct sleep_table sleeptable;

#define QUEUE_SIZE (10)

struct queue {
	struct entry entries[QUEUE_SIZE];
	int next_prod_idx;
	int next_cons_idx;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

#define MAX_THREADS (40)

struct queue printqueue;
pthread_t printthread[MAX_THREADS];
pthread_mutex_t print_mtx = PTHREAD_MUTEX_INITIALIZER;
#define PRINT_BUFFER_SIZE (16 * 1024 * 1024)

static __always_inline void *malloc_or_die(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL)
		err(0, "malloc() failed");
	return ptr;
}

static __always_inline void write_or_die(int fd, const char *buf, size_t count)
{
	ssize_t r;

	do {
		r = write(fd, buf, count);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			err(0, "write() failed");
		}
		count -= r;
		buf += r;
	} while (count > 0);
}

static __always_inline void clock_gettime_or_die(clockid_t clk_id,
						 struct timespec *tp)
{
	int r = clock_gettime(clk_id, tp);

	if (r != 0)
		err(0, "clock_gettime() failed");
}

static void open_stdout(void)
{
	if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
		err(0, "setvbuf() failed");
	fd_stdout = fileno(stdout);
	if (fd_stdout < 0)
		err(0, "fileno() failed");
}

static __always_inline void get_time_in_future(struct timespec *future,
					       long time_us)
{
	long nsec;

	clock_gettime_or_die(CLOCK_MONOTONIC, future);
	future->tv_sec += time_us / USEC_PER_SEC;
	nsec = future->tv_nsec + (time_us * NSEC_PER_USEC) % NSEC_PER_SEC;
	if (nsec >= NSEC_PER_SEC) {
		future->tv_nsec = nsec % NSEC_PER_SEC;
		future->tv_sec += 1;
	}
}

static __always_inline bool time_has_passed(const struct timespec *time)
{
	struct timespec now;

	clock_gettime_or_die(CLOCK_MONOTONIC, &now);
	if (now.tv_sec > time->tv_sec)
		return true;
	if (now.tv_sec < time->tv_sec)
		return false;
	return (now.tv_nsec >= time->tv_nsec);
}

static void init_printstate(void)
{
	pthread_condattr_t attr;

	printstate.ticket_counter = 0;
	printstate.ticket_completed = 0;
	printstate.cnt = 0;

	if (pthread_mutex_init(&printstate.mutex, NULL) != 0)
		err(0, "pthread_mutex_init() failed");

	if (pthread_mutex_init(&printstate.cnt_mutex, NULL) != 0)
		err(0, "pthread_mutex_init() failed");

	if (pthread_condattr_init(&attr) != 0)
		err(0, "pthread_condattr_init()");

	if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0)
		err(0, "pthread_condattr_setclock()");

	if (pthread_cond_init(&printstate.cond, &attr) != 0)
		err(0, "pthread_cond_init() failed");
}

static __always_inline void mutex_lock(pthread_mutex_t *mtx)
{
	if (pthread_mutex_lock(mtx) != 0)
		err(0, "pthread_mutex_lock() failed");
}

static __always_inline void mutex_unlock(pthread_mutex_t *mtx)
{
	if (pthread_mutex_unlock(mtx) != 0)
		err(0, "pthread_mutex_unlock() failed");
}

static __always_inline void cond_signal(pthread_cond_t *cond)
{
	if (pthread_cond_signal(cond) != 0)
		err(0, "pthread_cond_signal() failed");
}

static __always_inline void cond_broadcast(pthread_cond_t *cond)
{
	if (pthread_cond_broadcast(cond) != 0)
		err(0, "pthread_cond_broadcast() failed");
}

static int printstate_next_ticket(struct entry *req)
{
	int r;

	r = ++(printstate.ticket_counter);
	req->ticket = r;
	req->ticket_completed_ref = printstate.ticket_completed;
	cond_broadcast(&printstate.cond);
	return r;
}

static __always_inline
void printstate_mark_req_completed(const struct entry *req)
{
	if (req->ticket > printstate.ticket_completed)
		printstate.ticket_completed = req->ticket;
}

static __always_inline
bool printstate_has_new_req_arrived(const struct entry *req)
{
	return (printstate.ticket_counter != req->ticket);
}

static __always_inline int printstate_cnt_inc(void)
{
	int value;

	mutex_lock(&printstate.cnt_mutex);
	value = ++printstate.cnt;
	mutex_unlock(&printstate.cnt_mutex);
	return value;
}

static __always_inline int printstate_cnt_dec(void)
{
	int value;

	mutex_lock(&printstate.cnt_mutex);
	value = --printstate.cnt;
	mutex_unlock(&printstate.cnt_mutex);
	return value;
}

static __always_inline int printstate_cnt_read(void)
{
	int value;

	mutex_lock(&printstate.cnt_mutex);
	value = printstate.cnt;
	mutex_unlock(&printstate.cnt_mutex);
	return value;
}

static __always_inline
bool prev_req_won_race(const struct entry *req)
{
	return (printstate.ticket_completed != req->ticket_completed_ref);
}

static void sleeptable_resize(int size, bool printout, struct short_msg *msg)
{
	int bytes;

	if (printout) {
		msg->len = 0;
		if (unlikely(size > PROB_TABLE_MAX_SIZE))
			bytes = snprintf(msg->buf, sizeof(msg->buf),
"Cannot increase probability table to %d (maximum size reached)\n", size);
		else
			bytes = snprintf(msg->buf, sizeof(msg->buf),
"Increasing probability table to %d\n", size);
		if (bytes < 0)
			warn("snprintf() failed");
		else
			msg->len = bytes;
	}

	if (unlikely(size < 0)) {
		/* Should never happen */
		errx(0, "Bad program state at %s:%d", __FILE__, __LINE__);
		return;
	}
	sleeptable.size = size;
	sleeptable.table = &probabilities[PROB_TABLE_MAX_SIZE - size];
}

static void init_probabilities(void)
{
	int i;
	int j = 1000;

	for (i = 0; i < PROB_TABLE_MAX_SIZE; i++) {
		probabilities[i] = 1000 / j;
		j--;
	}
	if (pthread_mutex_init(&sleeptable.mutex, NULL) != 0)
		err(0, "pthread_mutex_init() failed");
}

static int table_get_probability(const struct entry *req,
				 struct short_msg *msg)
{
	int diff = req->ticket - req->ticket_completed_ref;
	int rval = 0;

	msg->len = 0;
	diff--;
	/* Should never happen...*/
	if (diff < 0)
		errx(0, "Programmer assumption error at %s:%d\n", __FILE__,
		     __LINE__);
	mutex_lock(&sleeptable.mutex);
	if (diff >= (sleeptable.size - 1)) {
		rval = sleeptable.table[sleeptable.size - 1];
		sleeptable_resize(sleeptable.size + 1, verbose_sizechange(),
				  msg);
	} else {
		rval = sleeptable.table[diff];
	}
	mutex_unlock(&sleeptable.mutex);
	return rval;
}

static void init_queue(struct queue *q)
{
	q->next_prod_idx = 0;
	q->next_cons_idx = 0;
	if (pthread_mutex_init(&q->mutex, NULL) != 0)
		err(0, "pthread_mutex_init() failed");
	if (pthread_cond_init(&q->cond, NULL) != 0)
		err(0, "pthread_cond_init() failed");
}

static __always_inline int queue_len(const struct queue *q)
{
	if (q->next_prod_idx >= q->next_cons_idx)
		return q->next_prod_idx - q->next_cons_idx;
	else
		return QUEUE_SIZE - q->next_cons_idx + q->next_prod_idx;
}

static __always_inline int queue_nr_free(const struct queue *q)
{
	int nr_free = QUEUE_SIZE - queue_len(q);

	/*
	 * If there is only one slot left we will anyway lie and claim that the
	 * queue is full because adding an element will make it appear empty
	 */
	if (nr_free == 1)
		nr_free = 0;
	return nr_free;
}

static __always_inline void queue_idx_inc(int *idx)
{
	*idx = (*idx + 1) % QUEUE_SIZE;
}

static __always_inline void queue_push_to_back(struct queue *q,
					      const struct entry *e)
{
	q->entries[q->next_prod_idx] = *e;
	queue_idx_inc(&q->next_prod_idx);
}

static __always_inline struct entry queue_pop_from_front(struct queue *q)
{
	struct entry e = q->entries[q->next_cons_idx];

	queue_idx_inc(&q->next_cons_idx);
	return e;
}

static __always_inline void queue_cond_signal(struct queue *q)
{
	if (pthread_cond_signal(&q->cond) != 0)
		err(0, "pthread_cond_signal() failed");
}

static __always_inline void queue_cond_wait(struct queue *q)
{
	if (pthread_cond_wait(&q->cond, &q->mutex) != 0)
		err(0, "pthread_cond_wait() failed");
}


static __always_inline int queue_try_to_add_entry(struct queue *q,
						  const struct entry *e)
{
	int r = 0;

	mutex_lock(&q->mutex);
	if (queue_nr_free(q) > 0) {
		queue_push_to_back(q, e);
		cond_signal(&q->cond);
	} else
		r = -1;
	mutex_unlock(&q->mutex);
	return r;
}

static struct entry queue_wait_for_entry(struct queue *q)
{
	struct entry e;

	mutex_lock(&q->mutex);
	while (true) {
		if (queue_len(&printqueue) > 0) {
			e = queue_pop_from_front(q);
			break;
		}
		queue_cond_wait(q);
	}
	mutex_unlock(&q->mutex);

	return e;
}

static const struct policy *policy_from_name(const char *name)
{
	const struct policy *p = &policies[0];

	while (p->name != NULL) {
		if (!strcmp(name, p->name))
			return p;
		p++;
	}
	return NULL;
}

static const char *policy_name(int policy)
{
	const struct policy *p = &policies[0];
	static const char *rval = "unknown";

	while (p->name != NULL) {
		if (p->policy == policy)
			return p->name;
		p++;
	}
	return rval;
}

static bool toss_coin(struct drand48_data *buffer, unsigned int prob)
{
	long r;

	if (lrand48_r(buffer, &r) != 0)
		err(0, "lrand48_r() failed");
	r = r % 1000L;
	if (r < prob)
		return true;
	else
		return false;
}


static long go_to_sleep(const struct entry *req)
{
	struct timespec future;
	long delay = sleep_time;

	get_time_in_future(&future, delay);

	mutex_lock(&printstate.mutex);
	while (!printstate_has_new_req_arrived(req)) {
		if (pthread_cond_timedwait(&printstate.cond, &printstate.mutex,
					   &future) != 0) {
			if (errno != ETIMEDOUT && errno != 0)
				err(0, "pthread_cond_timedwait() %d", errno);
		}
		if (time_has_passed(&future))
			break;
	};

	if (printstate_has_new_req_arrived(req))
		delay = -1;
	mutex_unlock(&printstate.mutex);

	return delay;
}


static void set_priority(void)
{
	int r;
	pid_t pid;
	struct sched_param param;

	memset(&param, 0, sizeof(param));
	param.sched_priority = sched_pri;

	pid = getpid();
	r = sched_setscheduler(pid, sched_policy, &param);

	if (r != 0)
		err(0, "sched_setscheduler() failed");
}

pid_t latency_collector_gettid(void)
{
	return (pid_t) syscall(__NR_gettid);
}

static void print_priority(void)
{
	pid_t tid;
	int policy;
	int r;
	struct sched_param param;

	tid = latency_collector_gettid();
	r = pthread_getschedparam(pthread_self(), &policy, &param);
	if (r != 0)
		err(0, "pthread_getschedparam() failed");
	mutex_lock(&print_mtx);
	printf("Thread %d runs with scheduling policy %s and priority %d\n",
	       tid, policy_name(policy), param.sched_priority);
	mutex_unlock(&print_mtx);
}

static __always_inline
void __print_skipmessage(const struct short_msg *resize_msg,
			 const struct timespec *timestamp, char *buffer,
			 size_t bufspace, const struct entry *req, bool excuse,
			 const char *str)
{
	ssize_t bytes = 0;
	char *p = &buffer[0];
	long us, sec;
	int r;

	sec = timestamp->tv_sec;
	us = timestamp->tv_nsec / 1000;

	if (resize_msg != NULL && resize_msg->len > 0) {
		strncpy(p, resize_msg->buf, resize_msg->len);
		bytes += resize_msg->len;
		p += resize_msg->len;
		bufspace -= resize_msg->len;
	}

	if (excuse)
		r = snprintf(p, bufspace,
"%ld.%06ld Latency %d printout skipped due to %s\n",
			     sec, us, req->ticket, str);
	else
		r = snprintf(p, bufspace, "%ld.%06ld Latency %d detected\n",
			    sec, us, req->ticket);

	if (r < 0)
		warn("snprintf() failed");
	else
		bytes += r;

	/* These prints could happen concurrently */
	mutex_lock(&print_mtx);
	write_or_die(fd_stdout, buffer, bytes);
	mutex_unlock(&print_mtx);
}

static void print_skipmessage(const struct short_msg *resize_msg,
			      const struct timespec *timestamp, char *buffer,
			      size_t bufspace, const struct entry *req,
			      bool excuse)
{
	__print_skipmessage(resize_msg, timestamp, buffer, bufspace, req,
			    excuse, "random delay");
}

static void print_lostmessage(const struct timespec *timestamp, char *buffer,
			      size_t bufspace, const struct entry *req,
			      const char *reason)
{
	__print_skipmessage(NULL, timestamp, buffer, bufspace, req, true,
			    reason);
}

static void print_tracefile(const struct short_msg *resize_msg,
			    const struct timespec *timestamp, char *buffer,
			    size_t bufspace, long slept,
			    const struct entry *req)
{
	static const int reserve = 256;
	char *p = &buffer[0];
	ssize_t bytes = 0;
	ssize_t bytes_tot = 0;
	long us, sec;
	long slept_ms;
	int trace_fd;

	/* Save some space for the final string and final null char */
	bufspace = bufspace - reserve - 1;

	if (resize_msg != NULL && resize_msg->len > 0) {
		bytes = resize_msg->len;
		strncpy(p, resize_msg->buf, bytes);
		bytes_tot += bytes;
		p += bytes;
		bufspace -= bytes;
	}

	trace_fd = open(debug_tracefile, O_RDONLY);

	if (trace_fd < 0) {
		warn("open() failed on %s", debug_tracefile);
		return;
	}

	sec = timestamp->tv_sec;
	us = timestamp->tv_nsec / 1000;

	if (slept != 0) {
		slept_ms = slept / 1000;
		bytes = snprintf(p, bufspace,
"%ld.%06ld Latency %d randomly sleep for %ld ms before print\n",
				 sec, us, req->ticket, slept_ms);
	} else {
		bytes = snprintf(p, bufspace,
				 "%ld.%06ld Latency %d immediate print\n", sec,
				 us, req->ticket);
	}

	if (bytes < 0) {
		warn("snprintf() failed");
		return;
	}
	p += bytes;
	bufspace -= bytes;
	bytes_tot += bytes;

	bytes = snprintf(p, bufspace,
">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> BEGIN <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
		);

	if (bytes < 0) {
		warn("snprintf() failed");
		return;
	}

	p += bytes;
	bufspace -= bytes;
	bytes_tot += bytes;

	do {
		bytes = read(trace_fd, p, bufspace);
		if (bytes < 0) {
			if (errno == EINTR)
				continue;
			warn("read() failed on %s", debug_tracefile);
			if (close(trace_fd) != 0)
				warn("close() failed on %s", debug_tracefile);
			return;
		}
		if (bytes == 0)
			break;
		p += bytes;
		bufspace -= bytes;
		bytes_tot += bytes;
	} while (true);

	if (close(trace_fd) != 0)
		warn("close() failed on %s", debug_tracefile);

	printstate_cnt_dec();
	/* Add the reserve space back to the budget for the final string */
	bufspace += reserve;

	bytes = snprintf(p, bufspace,
			 ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> END <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n");

	if (bytes < 0) {
		warn("snprintf() failed");
		return;
	}

	bytes_tot += bytes;

	/* These prints could happen concurrently */
	mutex_lock(&print_mtx);
	write_or_die(fd_stdout, buffer, bytes_tot);
	mutex_unlock(&print_mtx);
}

static void do_jittertest(void)
{
	int ifd = inotify_init();
	int wd;
	const ssize_t bufsize = sizeof(inotify_buffer);
	const ssize_t istructsize = sizeof(struct inotify_event);
	char *buf = &inotify_buffer[0];
	ssize_t nr_read;
	char *p;
	int modified;
	struct inotify_event *event;
	struct entry req;
	char *buffer;
	const size_t bufspace = PRINT_BUFFER_SIZE;
	struct timespec timestamp;

	print_priority();

	buffer = malloc_or_die(bufspace);

	if (ifd < 0)
		err(0, "inotify_init() failed!");

	wd = inotify_add_watch(ifd, debug_maxlat_file, IN_MODIFY);
	if (wd < 0)
		err(0, "inotify_add_watch() failed!");

	while (true) {
		modified = 0;
		nr_read = read(ifd, buf, bufsize);
		if (nr_read <= 0)
			err(0, "read() failed on inotify fd!");
		if (nr_read == bufsize)
			warnx("inotify() buffer filled, skipping events");
		if (nr_read < istructsize)
			errx(0, "read() returned too few bytes on inotify fd");

		for (p = buf; p < buf + nr_read;) {
			event = (struct inotify_event *) p;
			if ((event->mask & IN_MODIFY) != 0)
				modified++;
			p += istructsize + event->len;
		}
		while (modified > 0) {
			mutex_lock(&printstate.mutex);
			printstate_next_ticket(&req);
			if (printstate_cnt_read() > 0) {
				printstate_mark_req_completed(&req);
				mutex_unlock(&printstate.mutex);
				if (verbose_lostevent()) {
					clock_gettime_or_die(CLOCK_MONOTONIC,
							     &timestamp);
					print_lostmessage(&timestamp, buffer,
							  bufspace, &req,
							  "inotify loop");
				}
				break;
			}
			mutex_unlock(&printstate.mutex);
			if (queue_try_to_add_entry(&printqueue, &req) != 0) {
				/* These prints could happen concurrently */
				mutex_lock(&print_mtx);
				write_or_die(fd_stdout, queue_full_warning,
					     sizeof(queue_full_warning));
				mutex_unlock(&print_mtx);
			}
			modified--;
		}
	}
}

static void *do_printloop(void *arg)
{
	const size_t bufspace = PRINT_BUFFER_SIZE;
	char *buffer;
	long *rseed = (long *) arg;
	struct drand48_data drandbuf;
	long slept = 0;
	struct entry req;
	int prob = 0;
	struct timespec timestamp;
	struct short_msg resize_msg;

	print_priority();

	if (srand48_r(*rseed, &drandbuf) != 0)
		err(0, "srand48_r() failed!\n");

	buffer = malloc_or_die(bufspace);

	while (true) {
		req = queue_wait_for_entry(&printqueue);
		clock_gettime_or_die(CLOCK_MONOTONIC, &timestamp);
		mutex_lock(&printstate.mutex);
		if (prev_req_won_race(&req)) {
			printstate_mark_req_completed(&req);
			mutex_unlock(&printstate.mutex);
			if (verbose_lostevent())
				print_lostmessage(&timestamp, buffer, bufspace,
						  &req, "print loop");
			continue;
		}
		mutex_unlock(&printstate.mutex);

		/*
		 * Toss a coin to decide if we want to sleep a random amount
		 * before printing out the backtrace. The reason for this is
		 * that opening /sys/kernel/debug/tracing/trace will cause a
		 * blackout of about 430 ms, where no latencies will be noted
		 * by the latency tracer. Thus by randomly sleeping a random
		 * amount we try to avoid missing traces systematically due to
		 * this. With this option we will sometimes get the first
		 * latency, some other times some of the later ones, in case of
		 * closely spaced traces.
		 */
		if (trace_enable && use_random_sleep) {
			slept = 0;
			prob = table_get_probability(&req, &resize_msg);
			if (!toss_coin(&drandbuf, prob))
				slept = go_to_sleep(&req);
			if (slept >= 0) {
				/* A print is ongoing */
				printstate_cnt_inc();
				/*
				 * We will do the printout below so we have to
				 * mark it as completed while we still have the
				 * mutex.
				 */
				mutex_lock(&printstate.mutex);
				printstate_mark_req_completed(&req);
				mutex_unlock(&printstate.mutex);
			}
		}
		if (trace_enable) {
			/*
			 * slept < 0  means that we detected another
			 * notification in go_to_sleep() above
			 */
			if (slept >= 0)
				/*
				 * N.B. printstate_cnt_dec(); will be called
				 * inside print_tracefile()
				 */
				print_tracefile(&resize_msg, &timestamp, buffer,
						bufspace, slept, &req);
			else
				print_skipmessage(&resize_msg, &timestamp,
						  buffer, bufspace, &req, true);
		} else {
			print_skipmessage(&resize_msg, &timestamp, buffer,
					  bufspace, &req, false);
		}
	}
	return NULL;
}

static void start_printthread(void)
{
	unsigned int i;
	long *seed;
	int ufd;

	ufd = open(DEV_URANDOM, O_RDONLY);
	if (nr_threads > MAX_THREADS) {
		warnx(
"Number of requested print threads was %d, max number is %d\n",
		      nr_threads, MAX_THREADS);
		nr_threads = MAX_THREADS;
	}
	for (i = 0; i < nr_threads; i++) {
		seed = malloc_or_die(sizeof(*seed));
		if (ufd <  0 ||
		    read(ufd, seed, sizeof(*seed)) != sizeof(*seed)) {
			printf(
"Warning! Using trivial random nummer seed, since %s not available\n",
			DEV_URANDOM);
			fflush(stdout);
			*seed = i;
		}
		if (pthread_create(&printthread[i], NULL, do_printloop, seed)
		    != 0)
			err(0, "pthread_create()");
	}
	if (ufd > 0)
		close(ufd);
}

static void show_usage(void)
{
	printf(
"Usage: %s [OPTION]...\n\n"
"Collect closely occurring latencies from %s\n"
"when any of the following tracers are enabled: preemptirqsoff, preemptoff,\n"
"irqsoff, wakeup_dl, wakeup_rt, or wakeup. A tracer can be enabled by doing\n"
"something like this:\n\n"

"echo 1000 > /sys/kernel/debug/tracing/tracing_thresh\n"
"echo preemptirqsoff > /sys/kernel/debug/tracing/current_tracer\n\n"

"The occurrence of a latency is detected by monitoring the file\n"
"%s with inotify.\n\n"

"The following options are supported:\n"
"-c, --policy POL\tRun the program with scheduling policy POL. POL can be\n"
"\t\t\tother, batch, idle, rr or fifo. The default is rr. When\n"
"\t\t\tusing rr or fifo, remember that these policies may cause\n"
"\t\t\tother tasks to experience latencies.\n\n"

"-p, --priority PRI\tRun the program with priority PRI. The acceptable range\n"
"\t\t\tof PRI depends on the scheduling policy.\n\n"

"-n, --notrace\t\tIf latency is detected, do not print out the content of\n"
"\t\t\tthe trace file to standard output\n\n"

"-t, --threads NRTHR\tRun NRTHR threads for printing. Default is %d.\n\n"

"-r, --random\t\tArbitrarily sleep a certain amount of time, default\n"
"\t\t\t%ld ms, before reading the trace file. The\n"
"\t\t\tprobabilities for sleep are chosen so that the\n"
"\t\t\tprobability of obtaining any of a cluster of closely\n"
"\t\t\toccurring latencies are equal, i.e. we will randomly\n"
"\t\t\tchoose which one we collect from the trace file.\n\n"
"\t\t\tThis option is probably only useful with the irqsoff,\n"
"\t\t\tpreemptoff, and preemptirqsoff tracers.\n\n"

"-a, --nrlat NRLAT\tFor the purpose of arbitrary delay, assume that there\n"
"\t\t\tare no more than NRLAT clustered latencies. If NRLAT\n"
"\t\t\tlatencies are detected during a run, this value will\n"
"\t\t\tautomatically be increased to NRLAT + 1 and then to\n"
"\t\t\tNRLAT + 2 and so on. The default is %d. This option\n"
"\t\t\timplies -r. We need to know this number in order to\n"
"\t\t\tbe able to calculate the probabilities of sleeping.\n"
"\t\t\tSpecifically, the probabilities of not sleeping, i.e. to\n"
"\t\t\tdo an immediate printout will be:\n\n"
"\t\t\t1/NRLAT  1/(NRLAT - 1) ... 1/3  1/2  1\n\n"
"\t\t\tThe probability of sleeping will be:\n\n"
"\t\t\t1 - P, where P is from the series above\n\n"
"\t\t\tThis descending probability will cause us to choose\n"
"\t\t\tan occurrence at random. Observe that the final\n"
"\t\t\tprobability is 0, it is when we reach this probability\n"
"\t\t\tthat we increase NRLAT automatically. As an example,\n"
"\t\t\twith the default value of 2, the probabilities will be:\n\n"
"\t\t\t1/2  0\n\n"
"\t\t\tThis means, when a latency is detected we will sleep\n"
"\t\t\twith 50%% probability. If we ever detect another latency\n"
"\t\t\tduring the sleep period, then the probability of sleep\n"
"\t\t\twill be 0%% and the table will be expanded to:\n\n"
"\t\t\t1/3  1/2  0\n\n"

"-v, --verbose\t\tIncrease the verbosity. If this option is given once,\n"
"\t\t\tthen print a message every time that the NRLAT value\n"
"\t\t\tis automatically increased. If this option is given at\n"
"\t\t\tleast twice, then also print a warning for lost events.\n\n"

"-u, --time TIME\t\tArbitrarily sleep for a specified time TIME ms before\n"
"\t\t\tprinting out the trace from the trace file. The default\n"
"\t\t\tis %ld ms. This option implies -r.\n\n"

"-f, --tracefile FILE\tUse FILE as trace file. The default is\n"
"\t\t\t%s.\n\n"

"-m, --max-lat FILE\tUse FILE as tracing_max_latency file. The default is\n"
"\t\t\t%s\n\n"
,
prg_name, debug_tracefile_dflt, debug_maxlat_dflt, DEFAULT_NR_PRINTER_THREADS,
SLEEP_TIME_MS_DEFAULT, DEFAULT_TABLE_SIZE, SLEEP_TIME_MS_DEFAULT,
debug_tracefile_dflt, debug_maxlat_dflt);
}

static void scan_arguments(int argc, char *argv[])
{
	int c;
	int option_idx = 0;

	debug_tracefile = debug_tracefile_dflt;
	debug_maxlat_file = debug_maxlat_dflt;

	static struct option long_options[] = {
		{ "policy",	required_argument,	0, 'c' },
		{ "priority",	required_argument,	0, 'p' },
		{ "help",	no_argument,		0, 'h' },
		{ "notrace",	no_argument,		0, 'n' },
		{ "random",	no_argument,		0, 'r' },
		{ "nrlat",	required_argument,	0, 'a' },
		{ "threads",	required_argument,	0, 't' },
		{ "time",	required_argument,	0, 'u' },
		{ "verbose",	no_argument,		0, 'v' },
		{ "tracefile",	required_argument,	0, 'f' },
		{ "max-lat",	required_argument,	0, 'm' },
		{ 0,		0,			0,  0  }
	};
	const struct policy *p;
	int max, min;
	int value;

	while (true) {
		c = getopt_long(argc, argv, "c:p:hnra:t:u:vf:m:", long_options,
				&option_idx);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			p = policy_from_name(optarg);
			if (p != NULL) {
				sched_policy = p->policy;
				sched_policy_set = true;
				if (!sched_pri_set) {
					sched_pri = p->default_pri;
					sched_pri_set = true;
				}
			} else {
				warnx("Unknown scheduling %s\n", optarg);
				show_usage();
				exit(0);
			}
			break;
		case 'p':
			sched_pri = atoi(optarg);
			sched_pri_set = true;
			break;
		case 'h':
			show_usage();
			exit(0);
			break;
		case 'n':
			trace_enable = false;
			use_random_sleep = false;
			break;
		case 't':
			value = atoi(optarg);
			if (value > 0)
				nr_threads = value;
			else {
				warnx("NRTHR must be > 0\n");
				show_usage();
				exit(0);
			}
			break;
		case 'u':
			value = atoi(optarg);
			if (value < 0) {
				warnx("TIME must be >= 0\n");
				show_usage();
				exit(0);
			}
			trace_enable = true;
			use_random_sleep = true;
			sleep_time = value * USEC_PER_MSEC;
			break;
		case 'v':
			verbosity++;
			break;
		case 'r':
			trace_enable = true;
			use_random_sleep = true;
			break;
		case 'a':
			value = atoi(optarg);
			if (value <= 0) {
				warnx("NRLAT must be > 0\n");
				show_usage();
				exit(0);
			}
			trace_enable = true;
			use_random_sleep = true;
			table_startsize = value;
			break;
		case 'f':
			debug_tracefile = strdup(optarg);
			break;
		case 'm':
			debug_maxlat_file = strdup(optarg);
			break;
		default:
			show_usage();
			exit(0);
			break;
		}
	}

	if (!sched_policy_set) {
		sched_policy = SCHED_RR;
		sched_policy_set = true;
		if (!sched_pri_set) {
			sched_pri = RT_DEFAULT_PRI;
			sched_pri_set = true;
		}
	}

	max = sched_get_priority_max(sched_policy);
	min = sched_get_priority_min(sched_policy);

	if (sched_pri < min) {
		printf(
"ATTENTION: Increasing priority to minimum, which is %d\n", min);
		sched_pri = min;
	}
	if (sched_pri > max) {
		printf(
"ATTENTION: Reducing priority to maximum, which is %d\n", max);
		sched_pri = max;
	}
}

static void show_params(void)
{
	printf(
		"Running with scheduling policy %s and priority %d. Using %d print threads.\n",
		policy_name(sched_policy), sched_pri, nr_threads);
	if (trace_enable) {
		if (use_random_sleep) {
			printf(
"%s will be printed with random delay\n"
"Start size of the probability table:\t\t\t%d\n"
"Print a message when prob. table table changes size:\t%s\n"
"Print a warning when an event has been lost:\t\t%s\n"
"Sleep time is:\t\t\t\t\t\t%ld ms\n",
debug_tracefile,
table_startsize,
bool2str(verbose_sizechange()),
bool2str(verbose_lostevent()),
sleep_time / USEC_PER_MSEC);
		} else {
			printf("%s will be printed immediately\n",
			       debug_tracefile);
		}
	} else {
		printf("%s will not be printed\n",
		       debug_tracefile);
	}
}

int main(int argc, char *argv[])
{
	open_stdout();

	if (argc >= 1)
		prg_name = argv[0];
	else
		prg_name = prg_unknown;

	scan_arguments(argc, argv);
	show_params();

	init_printstate();
	if (use_random_sleep) {
		init_probabilities();
		if (verbose_sizechange())
			printf("Initializing probability table to %d\n",
			       table_startsize);
		sleeptable_resize(table_startsize, false, NULL);
	}
	set_priority();
	init_queue(&printqueue);
	start_printthread();
	do_jittertest();

	return 0;
}
