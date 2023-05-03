CURR_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
PARENT_DIR="$(dirname "$CURR_DIR")"

echo $PARENT_DIR

cp -rf $CURR_DIR/outputs/$1.out $PARENT_DIR/e9stuff/inputs