void fill_array_safe(int *arr, int n) {
    if (!arr || n <= 0) return;
    for (int i = 0; i < n; i++) {
        arr[i] = i * 2;
    }
}