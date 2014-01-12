bulk_volatility_scanner
=======================

Python script to run battery of Volatility plugins against a forensic memory image

Syntax:

python bulk_volatility_scanner.py [memory image] [memory profile] [list of plugins]

The [list of plugins] is a line-deliminated unix text file containing volatility plugin names, ie:
  pstree
  pslist
  netscan
etc.
