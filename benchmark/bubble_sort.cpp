#include <stdio.h>
#include <stdlib.h>
 
void bubble_sort (int *a, int n) {
    int i, t, j = n, s = 1;
    while (s) {
        s = 0;
        for (i = 1; i < j; i++) {
            if (a[i] < a[i - 1]) {
                t = a[i];
                a[i] = a[i - 1];
                a[i - 1] = t;
                s = 1;
            }
        }
        j--;
    }
}
 
int main () {
    int n = 999999999;
	int *a = (int *)malloc(n * sizeof(*a));
    int i;
    for (i = 0; i < n; i++)
		a[i] = i;
      //  printf("%d%s", a[i], i == n - 1 ? "\n" : " ");
    bubble_sort(a, n);
    //for (i = 0; i < n; i++)
      //  printf("%d%s", a[i], i == n - 1 ? "\n" : " ");
    return 0;
}
