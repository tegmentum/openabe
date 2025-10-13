/**
 * OpenABE Comprehensive Benchmark Suite
 *
 * Compares performance across:
 * - Platforms: Native vs WASM
 * - Backends: RELIC vs MCL
 * - Curves: BLS12-381 (default), BN254, etc.
 * - Operations: Setup, KeyGen, Encrypt, Decrypt
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <map>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;
using namespace chrono;

struct BenchmarkResult {
    string operation;
    string curve;
    double mean_ms;
    double stddev_ms;
    double min_ms;
    double max_ms;
    int iterations;
    size_t data_size;
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

void print_platform_info() {
    cout << "========================================" << endl;
    cout << "  OpenABE Comprehensive Benchmark" << endl;
    cout << "========================================" << endl;
    cout << endl;
    cout << "Platform Information:" << endl;

#ifdef __wasm__
    cout << "  Platform:  WebAssembly" << endl;
#else
    cout << "  Platform:  Native" << endl;
#ifdef __aarch64__
    cout << "  Arch:      ARM64" << endl;
#elif defined(__x86_64__)
    cout << "  Arch:      x86_64" << endl;
#endif
#endif

#if defined(BP_WITH_MCL)
    cout << "  Backend:   MCL" << endl;
#else
    cout << "  Backend:   RELIC" << endl;
#endif

    cout << "  Version:   " << fixed << setprecision(2)
         << (OpenABE_getLibraryVersion() / 100.0) << endl;
    cout << endl;
}

class CPABEBenchmark {
public:
    CPABEBenchmark(const string& curve_name, int iterations)
        : curve_(curve_name), iterations_(iterations) {}

    vector<BenchmarkResult> run_all() {
        vector<BenchmarkResult> results;

        cout << "=== CP-ABE Benchmark Suite ===" << endl;
        cout << "Curve: " << curve_ << ", Iterations: " << iterations_ << endl;
        cout << endl;

        results.push_back(benchmark_setup());
        results.push_back(benchmark_keygen());
        results.push_back(benchmark_encryption_simple());
        results.push_back(benchmark_encryption_complex());
        results.push_back(benchmark_decryption_matching());
        results.push_back(benchmark_decryption_nonmatching());

        return results;
    }

private:
    string curve_;
    int iterations_;

    BenchmarkResult benchmark_setup() {
        cout << "[1/6] Benchmarking setup..." << flush;
        vector<double> times;
        Timer timer;

        for (int i = 0; i < iterations_; i++) {
            OpenABECryptoContext cpabe("CP-ABE");
            timer.start();
            cpabe.generateParams();
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Setup (generateParams)";
        result.curve = curve_;
        result.iterations = iterations_;
        result.data_size = 0;
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_keygen() {
        cout << "[2/6] Benchmarking key generation..." << flush;
        vector<double> times;
        Timer timer;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            cpabe.keygen("attr1|attr2|attr3", "bench_key_" + to_string(i));
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Key Generation (3 attrs)";
        result.curve = curve_;
        result.iterations = iterations_;
        result.data_size = 0;
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_encryption_simple() {
        cout << "[3/6] Benchmarking encryption (simple)..." << flush;
        vector<double> times;
        Timer timer;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE CP-ABE";
        string ciphertext;

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            cpabe.encrypt("attr1", plaintext, ciphertext);
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Encryption (1 attr)";
        result.curve = curve_;
        result.iterations = iterations_;
        result.data_size = ciphertext.size();
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_encryption_complex() {
        cout << "[4/6] Benchmarking encryption (complex)..." << flush;
        vector<double> times;
        Timer timer;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE CP-ABE";
        string ciphertext;
        string policy = "((attr1 and attr2) or (attr3 and attr4))";

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            cpabe.encrypt(policy, plaintext, ciphertext);
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "Encryption (complex policy)";
        result.curve = curve_;
        result.iterations = iterations_;
        result.data_size = ciphertext.size();
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_decryption_matching() {
        cout << "[5/6] Benchmarking decryption (matching)..." << flush;
        vector<double> times;
        Timer timer;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        cpabe.keygen("attr1|attr2|attr3|attr4", "bench_user");

        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE CP-ABE";
        string ciphertext, recovered;
        cpabe.encrypt("attr1 and attr2", plaintext, ciphertext);

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            bool success = cpabe.decrypt("bench_user", ciphertext, recovered);
            times.push_back(timer.stop_ms());

            if (!success || recovered != plaintext) {
                cerr << "ERROR: Decryption failed on iteration " << i << "!" << endl;
                break;
            }
        }

        BenchmarkResult result;
        result.operation = "Decryption (matching)";
        result.curve = curve_;
        result.iterations = iterations_;
        result.data_size = ciphertext.size();
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_decryption_nonmatching() {
        cout << "[6/6] Benchmarking decryption (non-matching)..." << flush;
        vector<double> times;
        Timer timer;

        OpenABECryptoContext cpabe("CP-ABE");
        cpabe.generateParams();
        // Key with attrs that don't satisfy the policy
        cpabe.keygen("attr5|attr6", "bench_user_nomatch");

        string plaintext = "This is a test message for benchmarking encryption performance in OpenABE CP-ABE";
        string ciphertext, recovered;
        cpabe.encrypt("attr1 and attr2", plaintext, ciphertext);

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            bool success = cpabe.decrypt("bench_user_nomatch", ciphertext, recovered);
            times.push_back(timer.stop_ms());

            if (success) {
                cerr << "WARNING: Non-matching decryption unexpectedly succeeded!" << endl;
            }
        }

        BenchmarkResult result;
        result.operation = "Decryption (non-matching)";
        result.curve = curve_;
        result.iterations = iterations_;
        result.data_size = 0;
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }
};

class PKEBenchmark {
public:
    PKEBenchmark(const string& ec_curve, int iterations)
        : ec_curve_(ec_curve), iterations_(iterations) {}

    vector<BenchmarkResult> run_all() {
        vector<BenchmarkResult> results;

        cout << "=== PKE (Public Key Encryption) Benchmark Suite ===" << endl;
        cout << "Curve: " << ec_curve_ << ", Iterations: " << iterations_ << endl;
        cout << endl;

        results.push_back(benchmark_keygen());
        results.push_back(benchmark_encryption());
        results.push_back(benchmark_decryption());

        return results;
    }

private:
    string ec_curve_;
    int iterations_;

    BenchmarkResult benchmark_keygen() {
        cout << "[1/3] Benchmarking PKE key generation..." << flush;
        vector<double> times;
        Timer timer;

        OpenPKEContext pke(ec_curve_);

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            pke.keygen("pke_user_" + to_string(i));
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "PKE Key Generation";
        result.curve = ec_curve_;
        result.iterations = iterations_;
        result.data_size = 0;
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_encryption() {
        cout << "[2/3] Benchmarking PKE encryption..." << flush;
        vector<double> times;
        Timer timer;

        OpenPKEContext pke(ec_curve_);
        pke.keygen("pke_test");

        string plaintext = "This is a test message for benchmarking PKE encryption performance in OpenABE";
        string ciphertext;

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            bool success = pke.encrypt("pke_test", plaintext, ciphertext);
            times.push_back(timer.stop_ms());

            if (!success) {
                cerr << "ERROR: PKE encryption failed on iteration " << i << "!" << endl;
                break;
            }
        }

        BenchmarkResult result;
        result.operation = "PKE Encryption";
        result.curve = ec_curve_;
        result.iterations = iterations_;
        result.data_size = ciphertext.size();
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_decryption() {
        cout << "[3/3] Benchmarking PKE decryption..." << flush;
        vector<double> times;
        Timer timer;

        OpenPKEContext pke(ec_curve_);
        pke.keygen("pke_test");

        string plaintext = "This is a test message for benchmarking PKE encryption performance in OpenABE";
        string ciphertext, recovered;
        pke.encrypt("pke_test", plaintext, ciphertext);

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            bool success = pke.decrypt("pke_test", ciphertext, recovered);
            times.push_back(timer.stop_ms());

            if (!success || recovered != plaintext) {
                cerr << "ERROR: PKE decryption failed on iteration " << i << "!" << endl;
                break;
            }
        }

        BenchmarkResult result;
        result.operation = "PKE Decryption";
        result.curve = ec_curve_;
        result.iterations = iterations_;
        result.data_size = ciphertext.size();
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }
};

class PKSIGBenchmark {
public:
    PKSIGBenchmark(const string& ec_curve, int iterations)
        : ec_curve_(ec_curve), iterations_(iterations) {}

    vector<BenchmarkResult> run_all() {
        vector<BenchmarkResult> results;

        cout << "=== PKSIG (Digital Signature) Benchmark Suite ===" << endl;
        cout << "Curve: " << ec_curve_ << ", Iterations: " << iterations_ << endl;
        cout << endl;

        results.push_back(benchmark_keygen());
        results.push_back(benchmark_sign());
        results.push_back(benchmark_verify());

        return results;
    }

private:
    string ec_curve_;
    int iterations_;

    BenchmarkResult benchmark_keygen() {
        cout << "[1/3] Benchmarking PKSIG key generation..." << flush;
        vector<double> times;
        Timer timer;

        OpenPKSIGContext pksig(ec_curve_);

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            pksig.keygen("pksig_user_" + to_string(i));
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "PKSIG Key Generation";
        result.curve = ec_curve_;
        result.iterations = iterations_;
        result.data_size = 0;
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_sign() {
        cout << "[2/3] Benchmarking PKSIG signing..." << flush;
        vector<double> times;
        Timer timer;

        OpenPKSIGContext pksig(ec_curve_);
        pksig.keygen("pksig_test");

        string message = "This is a test message for benchmarking digital signature performance in OpenABE";
        string signature;

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            pksig.sign("pksig_test", message, signature);
            times.push_back(timer.stop_ms());
        }

        BenchmarkResult result;
        result.operation = "PKSIG Sign";
        result.curve = ec_curve_;
        result.iterations = iterations_;
        result.data_size = signature.size();
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }

    BenchmarkResult benchmark_verify() {
        cout << "[3/3] Benchmarking PKSIG verification..." << flush;
        vector<double> times;
        Timer timer;

        OpenPKSIGContext pksig(ec_curve_);
        pksig.keygen("pksig_test");

        string message = "This is a test message for benchmarking digital signature performance in OpenABE";
        string signature;
        pksig.sign("pksig_test", message, signature);

        for (int i = 0; i < iterations_; i++) {
            timer.start();
            bool success = pksig.verify("pksig_test", message, signature);
            times.push_back(timer.stop_ms());

            if (!success) {
                cerr << "ERROR: PKSIG verification failed on iteration " << i << "!" << endl;
                break;
            }
        }

        BenchmarkResult result;
        result.operation = "PKSIG Verify";
        result.curve = ec_curve_;
        result.iterations = iterations_;
        result.data_size = 0;
        calculate_stats(times, result);

        cout << " Done (" << fixed << setprecision(2) << result.mean_ms << " ms avg)" << endl;
        return result;
    }
};

void print_results_table(const vector<BenchmarkResult>& results) {
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

    // Find ciphertext size from encryption results
    for (const auto& r : results) {
        if (r.operation.find("Encryption") != string::npos && r.data_size > 0) {
            cout << endl;
            cout << "Ciphertext size: " << r.data_size << " bytes" << endl;
            break;
        }
    }

    cout << endl;
}

void print_usage(const char* prog_name) {
    cout << "Usage: " << prog_name << " [options]" << endl;
    cout << endl;
    cout << "Options:" << endl;
    cout << "  -c, --curve CURVE       Pairing curve for ABE (BLS12_381, BN254, etc.)" << endl;
    cout << "                          Default: BLS12_381" << endl;
    cout << "  -e, --ec-curve CURVE    EC curve for PKI (NIST_P256, NIST_P384, NIST_P521)" << endl;
    cout << "                          Default: NIST_P256" << endl;
    cout << "  -n, --iterations N      Number of iterations (default: 100)" << endl;
    cout << "  -s, --scheme SCHEME     Scheme to benchmark: cpabe, pke, pksig, all" << endl;
    cout << "                          Default: all" << endl;
    cout << "  -a, --all-curves        Benchmark all supported curves" << endl;
    cout << "  -h, --help              Show this help message" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  " << prog_name << " -s cpabe -c BLS12_381 -n 50" << endl;
    cout << "  " << prog_name << " -s pke -e NIST_P384" << endl;
    cout << "  " << prog_name << " -s all --all-curves" << endl;
    cout << endl;
}

int main(int argc, char* argv[]) {
    string curve = "BLS12_381";  // Default to BLS12-381
    string ec_curve = "NIST_P256";  // Default EC curve for PKI
    int iterations = 100;
    bool all_curves = false;
    string scheme = "all";  // Default: benchmark all schemes

    // Parse command line
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        if ((arg == "-c" || arg == "--curve") && i + 1 < argc) {
            curve = argv[++i];
        } else if ((arg == "-e" || arg == "--ec-curve") && i + 1 < argc) {
            ec_curve = argv[++i];
        } else if ((arg == "-n" || arg == "--iterations") && i + 1 < argc) {
            iterations = atoi(argv[++i]);
        } else if ((arg == "-s" || arg == "--scheme") && i + 1 < argc) {
            scheme = argv[++i];
        } else if (arg == "-a" || arg == "--all-curves") {
            all_curves = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            cerr << "Unknown option: " << arg << endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    print_platform_info();

    InitializeOpenABE();

    // Run CP-ABE benchmarks
    if (scheme == "cpabe" || scheme == "all") {
        vector<string> curves_to_test;
        if (all_curves) {
            curves_to_test = {"BLS12_381", "BN254"};
#if !defined(BP_WITH_MCL)
            // RELIC supports more curves
            curves_to_test.push_back("BN462");
            curves_to_test.push_back("BLS12_461");
#endif
        } else {
            curves_to_test.push_back(curve);
        }

        map<string, vector<BenchmarkResult>> all_results;

        for (const auto& test_curve : curves_to_test) {
            cout << "========================================" << endl;
            cout << "  Testing Curve: " << test_curve << endl;
            cout << "========================================" << endl;
            cout << endl;

            CPABEBenchmark benchmark(test_curve, iterations);
            auto results = benchmark.run_all();
            all_results[test_curve] = results;

            print_results_table(results);
        }

        // Print comparison if multiple curves tested
        if (all_curves && all_results.size() > 1) {
            cout << endl;
            cout << "========================================" << endl;
            cout << "  Cross-Curve Comparison (CP-ABE)" << endl;
            cout << "========================================" << endl;
            cout << endl;

            // Create comparison table
            cout << left << setw(35) << "Operation";
            for (const auto& test_curve : curves_to_test) {
                cout << right << setw(15) << test_curve;
            }
            cout << endl;
            cout << string(35 + 15 * curves_to_test.size(), '-') << endl;

            // Get operation list from first curve
            if (!all_results.empty() && !all_results.begin()->second.empty()) {
                const auto& first_results = all_results.begin()->second;

                for (size_t i = 0; i < first_results.size(); i++) {
                    const string& op = first_results[i].operation;
                    cout << left << setw(35) << op;

                    for (const auto& test_curve : curves_to_test) {
                        if (all_results.count(test_curve) && i < all_results[test_curve].size()) {
                            double mean = all_results[test_curve][i].mean_ms;
                            cout << right << setw(15) << fixed << setprecision(2) << mean;
                        } else {
                            cout << right << setw(15) << "N/A";
                        }
                    }
                    cout << endl;
                }
            }
            cout << endl;
        }
    }

    // Run PKE benchmarks
    if (scheme == "pke" || scheme == "all") {
        vector<string> ec_curves_to_test;
        if (all_curves) {
            ec_curves_to_test = {"NIST_P256", "NIST_P384", "NIST_P521"};
        } else {
            ec_curves_to_test.push_back(ec_curve);
        }

        for (const auto& test_ec_curve : ec_curves_to_test) {
            cout << "========================================" << endl;
            cout << "  Testing EC Curve: " << test_ec_curve << endl;
            cout << "========================================" << endl;
            cout << endl;

            PKEBenchmark pke_benchmark(test_ec_curve, iterations);
            auto results = pke_benchmark.run_all();
            print_results_table(results);
        }
    }

    // Run PKSIG benchmarks
    if (scheme == "pksig" || scheme == "all") {
        vector<string> ec_curves_to_test;
        if (all_curves) {
            ec_curves_to_test = {"NIST_P256", "NIST_P384", "NIST_P521"};
        } else {
            ec_curves_to_test.push_back(ec_curve);
        }

        for (const auto& test_ec_curve : ec_curves_to_test) {
            cout << "========================================" << endl;
            cout << "  Testing EC Curve: " << test_ec_curve << endl;
            cout << "========================================" << endl;
            cout << endl;

            PKSIGBenchmark pksig_benchmark(test_ec_curve, iterations);
            auto results = pksig_benchmark.run_all();
            print_results_table(results);
        }
    }

    // Print summary statistics
    cout << "========================================" << endl;
    cout << "  Benchmark Complete" << endl;
    cout << "========================================" << endl;
    cout << endl;

    ShutdownOpenABE();

    return 0;
}
