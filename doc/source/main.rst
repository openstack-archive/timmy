============
main.sh
============

Set environment variables for the environment::

  source ./env.sh

Command which should be lauched on master node::

  source ./local.sh

Get list nodes::

  source ./get_nodes.sh

Run the parser nodes::

  ./parse.py --nodes "${nodesf}.json" --cluster "$cluster" --template "$template" --rolesd "$rolesd" --extended="$extended" --fuel-version="$release" --req-files="$reqdir"| column -t > "${nodesf}.txt"

Create snapshot::

  source ./create-arc.sh
