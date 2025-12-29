/**
 * Simple OpenABE CP-ABE Benchmark
 *
 * Measures basic CP-ABE operations using the OpenABECryptoContext API
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;
using namespace chrono;

struct BenchmarkResult {
    string operation;
    double mean_ms;
    double stddev_ms;
    double min_ms;
    double max_ms;
    int iterations;
};

class Timer {
public:
    void start() { start_time = high_resolution_clock::now(); }

    double stop_ms() {
        auto end_time = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end_time - start_time);
        return duration.count() / 1000.0;
    }

private:
    high_resolution_clock::time_point start_time;
};

void calculate_stats(const vector<double>& times, BenchmarkResult& result) {
    if (times.empty()) {
        result.mean_ms = result.stddev_ms = result.min_ms = result.max_ms = 0.0;
        return;
    }

    result.mean_ms = 0.0;
    for (double t : times) result.mean_ms += t;
    result.mean_ms /= times.size();

    result.stddev_ms = 0.0;
    for (double t : times) {
        double diff = t - result.mean_ms;
        result.stddev_ms += diff * diff;
    }
    result.stddev_ms = sqrt(result.stddev_ms / times.size());

    result.min_ms = times[0];
    result.max_ms = times[0];
    for (double t : times) {
        if (t < result.min_ms) result.min_ms = t;
        if (t > result.max_ms) result.max_ms = t;
    }
}

void print_result(const BenchmarkResult& r) {
    cout << left << setw(35) << r.operation
         << right << setw(12) << fixed << setprecision(2) << r.mean_ms
         << setw(12) << fixed << setprecision(2) << r.stddev_ms
         << setw(12) << fixed << setprecision(2) << r.min_ms
         << setw(12) << fixed << setprecision(2) << r.max_ms
         << endl;
}

int main(int argc, char* argv[]) {
    int iterations = 10;

    // Parse command line
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if ((arg == "-n" || arg == "--iterations") && i + 1 < argc) {
            iterations = atoi(argv[++i]);
        } else if (arg == "-h" || arg == "--help") {
            cout << "Usage: " << argv[0] << " [-n iterations]" << endl;
            return 0;
        }
    }

    cout << "========================================" << endl;
    cout << "  OpenABE CP-ABE Simple Benchmark" << endl;
    cout << "========================================" << endl;
    cout << endl;
    cout << "Scheme: CP-ABE (CCA-secure)" << endl;
    cout << "Iterations: " << iterations << endl;
    cout << endl;

    InitializeOpenABE();

    vector<BenchmarkResult> results;
    Timer timer;

    // Benchmark 1: Setup (generateParams)
    {
        cout << "[1/5] Benchmarking setup..." << flush;
        vector<double> times;

        for (int i = 0; i < iterations; i++) {
            OpenABECryptoContext cpabe("CP-ABE");
            timer.start();
            cpabe.generateParams();
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Setup (generateParams)";
        result.iterations = iterations;
        calculate_stats(times, result);
        results.push_back(result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
    }

    // Benchmark 2: Key Generation
    {
        cout << "[2/5] Benchmarking key generation..." << flush;
        vector<double> times;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();

        for (int i = 0; i < iterations; i++) {
            timer.start();
            cpabe.keygen("attr1|attr2|attr3", "bench_key_" + to_string(i));
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Key Generation (3 attrs)";
        result.iterations = iterations;
        calculate_stats(times, result);
        results.push_back(result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
    }

    // Benchmark 3: Encryption (simple policy)
    {
        cout << "[3/5] Benchmarking encryption (simple)..." << flush;
        vector<double> times;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE";
        string ciphertext;

        for (int i = 0; i < iterations; i++) {
            timer.start();
            cpabe.encrypt("attr1", plaintext, ciphertext);
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Encryption (1 attr)";
        result.iterations = iterations;
        calculate_stats(times, result);
        results.push_back(result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
    }

    // Benchmark 4: Encryption (complex policy)
    {
        cout << "[4/5] Benchmarking encryption (complex)..." << flush;
        vector<double> times;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE";
        string ciphertext;

        for (int i = 0; i < iterations; i++) {
            timer.start();
            cpabe.encrypt("((attr1 and attr2) or (attr3 and attr4))", plaintext, ciphertext);
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Encryption (complex policy)";
        result.iterations = iterations;
        calculate_stats(times, result);
        results.push_back(result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
    }

    // Benchmark 5: Decryption
    {
        cout << "[5/5] Benchmarking decryption..." << flush;
        vector<double> times;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        cpabe.keygen("attr1|attr2|attr3", "bench_user");

        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE";
        string ciphertext, recovered;
        cpabe.encrypt("attr1 and attr2", plaintext, ciphertext);

        for (int i = 0; i < iterations; i++) {
            timer.start();
            bool success = cpabe.decrypt("bench_user", ciphertext, recovered);
            times.push_back(timer.stop_ms());

            if (!success || recovered != plaintext) {
                cerr << "ERROR: Decryption failed!" << endl;
                break;
            }
        }

        BenchmarkResult result;
        result.operation = "Decryption (matching)";
        result.iterations = iterations;
        calculate_stats(times, result);
        results.push_back(result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
    }

    // Print results summary
    cout << endl;
    cout << "=== Benchmark Results Summary ===" << endl;
    cout << left << setw(35) << "Operation"
         << right << setw(12) << "Mean (ms)"
         << setw(12) << "StdDev"
         << setw(12) << "Min"
         << setw(12) << "Max" << endl;
    cout << string(83, '-') << endl;

    for (const auto& r : results) {
        print_result(r);
    }

    cout << endl;

    ShutdownOpenABE();

    return 0;
}
