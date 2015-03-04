=======================================
Get nodes
=======================================

Set environment variables for the environment::

   source ./env.sh

Get list and assign available nodes to environments::

   fuel node list --json > "${nodesf}.json" || exit

