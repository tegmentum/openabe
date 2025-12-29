/**
 * Test program for policy grammar and canonicalization
 *
 * This program demonstrates:
 * 1. Policy parsing from string
 * 2. Canonical string representation
 * 3. Equivalence testing via canonicalization
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

struct TestCase {
    string name;
    string policy1;
    string policy2;
    bool should_be_equal;
};

void print_separator() {
    cout << string(80, '=') << endl;
}

void print_policy_info(const string& label, const string& policy_str) {
    cout << label << endl;
    cout << "  Input:     " << policy_str << endl;

    auto policy = createPolicyTree(policy_str);
    if (policy) {
        cout << "  toString:  " << policy->toString() << endl;
        cout << "  Canonical: " << policy->toCanonicalString() << endl;
    } else {
        cout << "  ERROR: Failed to parse policy" << endl;
    }
    cout << endl;
}

void test_basic_parsing() {
    print_separator();
    cout << "Test 1: Basic Policy Parsing" << endl;
    print_separator();

    vector<string> test_policies = {
        "admin",
        "(admin and manager)",
        "(admin or manager)",
        "((admin and manager) or supervisor)",
        // Note: Threshold gate syntax "k of (...)" not yet supported by parser
        // "2 of (admin, manager, supervisor)",
        "age >= 18",
        "security_level in {1-5}",
    };

    for (const auto& policy_str : test_policies) {
        print_policy_info("Policy", policy_str);
    }
}

void test_canonicalization() {
    print_separator();
    cout << "Test 2: Canonicalization - Equivalent Policies" << endl;
    print_separator();

    vector<TestCase> test_cases = {
        {
            "Commutativity (AND)",
            "(admin and manager)",
            "(manager and admin)",
            true
        },
        {
            "Commutativity (OR)",
            "(admin or manager)",
            "(manager or admin)",
            true
        },
        {
            "Multi-attribute sorting",
            "(zebra or apple or monkey)",
            "(apple or monkey or zebra)",
            true
        },
        {
            "Nested policies",
            "((admin and dept) or manager)",
            "(manager or (dept and admin))",
            true
        },
        {
            "Different policies",
            "(admin and manager)",
            "(admin or manager)",
            false
        }
        // Note: Threshold gate tests commented out - parser doesn't support "k of (...)" syntax yet
        // {
        //     "Threshold equivalence (AND)",
        //     "(admin and manager)",
        //     "2 of (admin, manager)",
        //     true
        // },
        // {
        //     "Threshold equivalence (OR)",
        //     "(admin or manager)",
        //     "1 of (admin, manager)",
        //     true
        // }
    };

    for (const auto& test : test_cases) {
        cout << "Test: " << test.name << endl;
        cout << "  Policy 1: " << test.policy1 << endl;
        cout << "  Policy 2: " << test.policy2 << endl;

        auto p1 = createPolicyTree(test.policy1);
        auto p2 = createPolicyTree(test.policy2);

        if (p1 && p2) {
            string canon1 = p1->toCanonicalString();
            string canon2 = p2->toCanonicalString();

            cout << "  Canonical 1: " << canon1 << endl;
            cout << "  Canonical 2: " << canon2 << endl;

            bool are_equal = (canon1 == canon2);
            cout << "  Equal: " << (are_equal ? "YES" : "NO");

            if (are_equal == test.should_be_equal) {
                cout << " [PASS]" << endl;
            } else {
                cout << " [FAIL - Expected " << (test.should_be_equal ? "YES" : "NO") << "]" << endl;
            }
        } else {
            cout << "  ERROR: Failed to parse one or both policies" << endl;
        }

        cout << endl;
    }
}

void test_numeric_comparisons() {
    print_separator();
    cout << "Test 3: Numeric Comparisons and Ranges" << endl;
    print_separator();

    vector<string> numeric_policies = {
        "age >= 18",
        "age < 65",
        "security_level == 5",
        "(age >= 18 and age < 65)",
        "priority in (1-10)",
        "level in {3-7}",
    };

    for (const auto& policy_str : numeric_policies) {
        print_policy_info("Numeric Policy", policy_str);
    }
}

void test_complex_policies() {
    print_separator();
    cout << "Test 4: Complex Policy Combinations" << endl;
    print_separator();

    vector<string> complex_policies = {
        "((admin or manager) and (age >= 21 and security_level >= 5))",
        // Note: Threshold gate syntax not supported by parser yet
        // "(2 of (admin, manager, supervisor) and verified)",
        "((dept:engineering or dept:research) and clearance >= 7)",
    };

    for (const auto& policy_str : complex_policies) {
        print_policy_info("Complex Policy", policy_str);
    }
}

int main(int argc, char* argv[]) {
    cout << "========================================" << endl;
    cout << "  OpenABE Policy Grammar & Canonicalization Test" << endl;
    cout << "========================================" << endl;
    cout << endl;

    InitializeOpenABE();

    try {
        test_basic_parsing();
        test_canonicalization();
        test_numeric_comparisons();
        test_complex_policies();

        print_separator();
        cout << "All tests completed!" << endl;
        print_separator();
    } catch (const exception& e) {
        cerr << "Exception caught: " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }

    ShutdownOpenABE();
    return 0;
}
