cd ~/workspace/ledger

# 1. Lines needing the AppendSignature fix + ~3 lines context each
sed -n '125,132p'   tests/http_integration_test.go
echo "---"
sed -n '730,740p'   tests/http_integration_test.go  
echo "---"
sed -n '85,95p'     tests/integration_test.go
echo "==="

# 2. Context of the broken call
sed -n '160,175p'   tests/destination_binding_test.go
echo "---"

# 3. What test helpers actually exist today
grep -rn "^func.*[Tt]estServer\|^func newTest" tests/*.go | grep -v _test.go:.*//

# 4. What destination_binding_test.go expects the helper to do
grep -n "newTestServer\|testServer" tests/destination_binding_test.go | head -20