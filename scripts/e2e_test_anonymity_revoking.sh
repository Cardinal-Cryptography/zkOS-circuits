# You can
#
# $ln -s <zkOS-monorepo path on your system> zkOS-monorepo to test this
#
# script locally.

set -eu

cd zkOS-monorepo || exit 1

SCENARIO_OUTPUT=/tmp/full_scenario_output.txt
TERM=xterm KEEP_NODE=true BUILD=docker ./tooling-e2e-tests/full_scenario.sh > $SCENARIO_OUTPUT

NODE_ADDRESS=`cat $SCENARIO_OUTPUT | grep -oP "(?<=Node address: ).*" | xargs | head -n 1`
CONTRACT_ADDRESS=`cat $SCENARIO_OUTPUT | grep -oP "(?<=Contract address: ).*" | xargs | head -n 1`
ID_HASH=`cat $SCENARIO_OUTPUT | sed -n "/NewAccount/,/)/p" | grep -oP "(?<=revoking_marker: )\d*" | head -n 1`
EXPECTED_DEPOSIT=`cat $SCENARIO_OUTPUT | sed -n "/Deposit/,/)/p" | grep -oP "(?<=revoking_marker: ).*" | head -n 1`
EXPECTED_WITHDRAW=`cat $SCENARIO_OUTPUT | sed -n "/Withdraw {/,/}/p" | grep -oP "(?<=revoking_marker: ).*" | head -n 1`

if [[ -z "$EXPECTED_DEPOSIT" ]]; then
  echo "Expected deposit not found in scenario output"
  exit 1
fi

if [[ -z "$EXPECTED_WITHDRAW" ]]; then
  echo "Expected withdraw not found in scenario output"
  exit 1
fi

cd ../crates/shielder-anonymity-revoking || exit 1

cargo run --release -- \
  --id-hash "$ID_HASH" \
  chain \
  --node http://localhost:8545 \
  --contract-address "$CONTRACT_ADDRESS"

if [[ $(< deposit_native.csv) != *"$EXPECTED_DEPOSIT"* ]]; then
  echo "Expected deposit not found in revoking output"
  exit 1
fi

if [[ $(< withdraw_native.csv) != *"$EXPECTED_WITHDRAW"* ]]; then
  echo "Expected withdraw not found in revoking output"
  exit 1
fi

echo "Anonymity revoking test passed"
