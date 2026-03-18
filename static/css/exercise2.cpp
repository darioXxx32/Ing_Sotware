#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace std;
using namespace chrono;

// Binary Search
int binarySearch(const vector<int>& arr, int key) {
    int left = 0;
    int right = (int)arr.size() - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;

        if (arr[mid] == key)
            return mid;
        else if (arr[mid] < key)
            left = mid + 1;
        else
            right = mid - 1;
    }

    return -1;
}

// Interpolation Search
int interpolationSearch(const vector<int>& arr, int key) {
    int low = 0;
    int high = (int)arr.size() - 1;

    while (low <= high && key >= arr[low] && key <= arr[high]) {
        if (low == high) {
            if (arr[low] == key)
                return low;
            return -1;
        }

        if (arr[high] == arr[low])
            break;

        int pos = low + (double)(high - low) * (key - arr[low]) / (arr[high] - arr[low]);

        if (pos < low || pos > high)
            break;

        if (arr[pos] == key)
            return pos;
        else if (arr[pos] < key)
            low = pos + 1;
        else
            high = pos - 1;
    }

    return -1;
}

int main() {
    const int n = 10000000;
    vector<int> arr(n);

    srand((unsigned)time(0));

    cout << "Generating " << n << " random numbers..." << endl;
    for (int i = 0; i < n; i++) {
        arr[i] = rand();
    }

    cout << "Sorting array..." << endl;
    sort(arr.begin(), arr.end());

    // choose a key that definitely exists
    int key = arr[n / 2];

    cout << "Key searched: " << key << endl;

    // Binary Search timing
    auto startBinary = high_resolution_clock::now();
    int binaryIndex = binarySearch(arr, key);
    auto endBinary = high_resolution_clock::now();

    auto binaryTime = duration_cast<microseconds>(endBinary - startBinary);

    // Interpolation Search timing
    auto startInterpolation = high_resolution_clock::now();
    int interpolationIndex = interpolationSearch(arr, key);
    auto endInterpolation = high_resolution_clock::now();

    auto interpolationTime = duration_cast<microseconds>(endInterpolation - startInterpolation);

    cout << "\n--- Results ---" << endl;
    cout << "Binary Search index: " << binaryIndex << endl;
    cout << "Binary Search time: " << binaryTime.count() << " microseconds" << endl;

    cout << "Interpolation Search index: " << interpolationIndex << endl;
    cout << "Interpolation Search time: " << interpolationTime.count() << " microseconds" << endl;

    return 0;
}