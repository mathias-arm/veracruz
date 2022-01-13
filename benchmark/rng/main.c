#include <stdio.h>
#include <sys/random.h>
#include <sys/time.h>
#include <time.h>

int main() {
	char buf[64];
	unsigned int count = 0;
	clock_t t1, t2;
	size_t ret;
	struct timeval tval_before, tval_after, tval_result;

	while (1) {
		ret = getrandom(buf, 256, GRND_RANDOM | GRND_NONBLOCK);
		if (ret == -1) {
			gettimeofday(&tval_before, NULL);
			ret = getrandom(buf, 64, GRND_RANDOM);
			gettimeofday(&tval_after, NULL);
			timersub(&tval_after, &tval_before, &tval_result);
			printf("no entropy left. had to wait for entropy for %ld.%06ld\n", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
		}
		count++;
		printf("count=%d ret=%d\n", count, ret);
	}

	return 0;
}
