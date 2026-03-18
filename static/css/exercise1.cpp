#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

void insertionSort(char arr[], int n) {
    for(int i = 1; i < n; i++) {
        char key = arr[i];
        int j = i - 1;

        while(j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }

        arr[j + 1] = key;
    }
}

void printArray(char arr[], int n) {
    for(int i = 0; i < n; i++) {
        cout << arr[i] << " ";
    }
    cout << endl;
}

int main() {
    srand(time(0));

    const int n = 10;
    char arr[n];

    for(int i = 0; i < n; i++) {
        arr[i] = 'A' + rand() % 26;
    }

    cout << "Original array: ";
    printArray(arr, n);

    insertionSort(arr, n);

    cout << "Sorted array: ";
    printArray(arr, n);

    return 0;
}