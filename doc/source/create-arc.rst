============================================
Create archive with snapshot: create-arc.sh 
============================================

Set environment variables for the environment::

   source ./env.sh

Create archive::
   
   tar jcf ../timmy-snap-${dlabel}-min.tar.bz2 ../$dn --exclude="../$dn/${filesd}"
   tar jcf ../timmy-snap-${dlabel}-all.tar.bz2 ../$dn


