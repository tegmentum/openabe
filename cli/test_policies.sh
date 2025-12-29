#!/bin/bash
echo "Testing various CP-ABE policy patterns..."
echo ""

test_policy() {
    local desc="$1"
    local policy="$2"
    local plaintext="Test: $desc"
    
    echo "$plaintext" > test_tmp.txt
    ./oabe_enc -s CP -p test -e "$policy" -i test_tmp.txt -o test_tmp.cpabe 2>&1 | grep -q "ERROR" && {
        echo "❌ $desc - encryption failed"
        return 1
    }
    ./oabe_dec -s CP -p test -k user.key -i test_tmp.cpabe -o test_tmp_dec.txt 2>&1 | grep -q "ERROR" && {
        echo "❌ $desc - decryption failed"
        return 1
    }
    diff -q test_tmp.txt test_tmp_dec.txt > /dev/null && {
        echo "✅ $desc"
        return 0
    } || {
        echo "❌ $desc - content mismatch"
        return 1
    }
}

# Test various policy patterns
test_policy "2-attribute AND" "(one and two)"
test_policy "3-attribute AND" "(one and two and three)"
test_policy "4-attribute AND" "(one and two and three and four)"
test_policy "2-attribute OR" "(one or two)"
test_policy "3-attribute OR" "(one or two or three)"
test_policy "Mixed AND/OR" "((one and two) or three)"
test_policy "Threshold 2-of-3" "2 of (one, two, three)"
test_policy "Threshold 3-of-4" "3 of (one, two, three, four)"

# Cleanup
rm -f test_tmp.txt test_tmp.cpabe test_tmp_dec.txt
