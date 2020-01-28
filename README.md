# latency-collector

## Summary

This is a tool that is intended to work around the fact that the
preemptoff, irqsoff, and preemptirqsoff tracers only work in
overwrite mode.

I originally posted this to the LKML [here](https://lkml.org/lkml/2019/10/18/786)

## How to build

You can build this tool by doing this:

```
cd tools/trace
make
```

You will need a kernel with [this patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=91edde2e6ae1dd5e33812f076f3fe4cb7ccbfdd0). It may also be good to have [this patch](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=793937236d1ee032d2ee5ccc27bdd280a04e766e), in order to test the tool. For mainline, this means v5.5 or newer.

## How it works

The idea is to act randomly in such a way that we
do not systematically lose any latencies, so that if enough testing
is done, all latencies will be captured. If the same burst of
latencies is repeated, then sooner or later we will have captured all
the latencies.

The reason why it may be desirable to catch all latencies with a long
test campaign is that for some organizations, it's necessary to test
the kernel in the field and not practical for developers to work
iteratively with field testers. Because of cost and project schedules
it is not possible to start a new test campaign every time a latency
problem has been fixed.

It uses inotify to detect changes to `/sys/kernel/debug/tracing/trace`.
When a latency is detected, it will either sleep or print
immediately, depending on a function that act as an unfair coin
toss.

If immediate print is chosen, it means that we open
`/sys/kernel/debug/tracing/trace` and thereby cause a blackout period
that will hide any subsequent latencies.

If sleep is chosen, it means that we wait before opening
`/sys/kernel/debug/tracing/trace`, by default for 1000 ms, to see if
there is another latency during this period. If there is, then we will
lose the previous latency. The coin will be tossed again with a
different probability, and we will either print the new latency, or
possibly a subsequent one.

The probability for the unfair coin toss is chosen so that there
is equal probability to obtain any of the latencies in a burst.
However, this assumes that we make an assumption of how many
latencies there can be. By default  the program assumes that there
are no more than 2 latencies in a burst, the probability of immediate
printout will be:

```
1/2 and 1
```

Thus, the probability of getting each of the two latencies will be 1/2.

If we ever find that there is more than one latency in a series,
meaning that we reach the probability of 1, then the table will be
expanded to:

```
1/3, 1/2, and 1
```

Thus, we assume that there are no more than three latencies and each
with a probability of 1/3 of being captured. If the probability of 1
is reached in the new table, that is we see more than two closely
occurring latencies, then the table will again be extended, and so
on.

On my systems, it seems like this scheme works fairly well, as
long as the latencies we trace are long enough, 100 us seems to be
enough. This userspace program receive the inotify event at the end
of a latency, and it has time until the end of the next latency
to react, that is to open /sys/kernel/debug/tracing/trace. Thus,
if we trace latencies that are >100 us, then we have at least 100 us
to react.

Example output:

```
root@myhost:~# echo 100 > /sys/kernel/debug/tracing/tracing_thresh
root@myhost:~# echo preemptirqsoff > /sys/kernel/debug/tracing/current_tracer
root@myhost:~# latency-collector -rvv -a 11 &
[1] 4915
root@myhost:~# Running with policy rr and priority 99. Using 3 print threads.
/sys/kernel/debug/tracing/trace will be printed with random delay
Start size of the probability table:                    11
Print a message when prob. table table changes size:    true
Print a warning when an event has been lost:            true
Sleep time is:                                          1000 ms
Initializing probability table to 11
Thread 4916 runs with policy rr and priority 99
Thread 4917 runs with policy rr and priority 99
Thread 4918 runs with policy rr and priority 99
Thread 4919 runs with policy rr and priority 99

root@myhost:~# modprobe preemptirq_delay_test delay=105 test_mode=alternate burst_size=10
2850.638308 Latency 1 printout skipped due to random delay
2850.638383 Latency 2 printout skipped due to random delay
2850.638497 Latency 3 immediate print
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> BEGIN <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
alternat-4922    6d...    0us!: execute_preemptirqtest <-preemptirqtest_2
alternat-4922    6d...  106us : execute_preemptirqtest <-preemptirqtest_2
alternat-4922    6d...  106us : tracer_hardirqs_on <-preemptirqtest_2
alternat-4922    6d...  108us : <stack trace>
 => preemptirqtest_2
 => preemptirq_delay_run
 => kthread
 => ret_from_fork
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> END <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

In the example above, we randomly, happened to get the third latency
in a burst burst of 10. If the experiment is repeated enough times,
we will get all 10.

Sometimes, there will be lost latencies, so that we get:

```
3054.078294 Latency 44 printout skipped due to inotify loop
```

...or:

```
3211.957685 Latency 112 printout skipped due to print loop
```

In my experience, these are not frequent enough to be a problem.

Also, we do not really lose any latency in these cases, it's
more like we get another latency than what was intended by
the design.
