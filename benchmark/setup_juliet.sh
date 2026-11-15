#!/usr/bin/env bash
# Script to fetch selected Juliet Test Suite testcases for memory corruption evaluation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${SCRIPT_DIR}/juliet"
REPO_URL="https://github.com/arichardson/juliet-test-suite-c.git"

echo "[*] Setting up Juliet Test Suite in: ${TARGET_DIR}"

if [ ! -d "${TARGET_DIR}/.git" ]; then
    echo "[*] Cloning repository metadata (sparse-checkout)..."
    git clone --filter=blob:none --no-checkout --depth 1 "${REPO_URL}" "${TARGET_DIR}"
fi

cd "${TARGET_DIR}"

echo "[*] Configuring sparse-checkout for memory corruption CWEs..."
git sparse-checkout init --cone
git sparse-checkout set \
    testcasesupport \
    testcases/CWE121_Stack_Based_Buffer_Overflow \
    testcases/CWE122_Heap_Based_Buffer_Overflow \
    testcases/CWE415_Double_Free \
    testcases/CWE416_Use_After_Free \
    testcases/CWE476_NULL_Pointer_Dereference

echo "[*] Checking out testcases..."
git checkout HEAD

echo "[+] Juliet Test Suite successfully set up!"
echo "    Total C testcases: $(find testcases -name '*.c' | wc -l)"
