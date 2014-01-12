bulk_volatility_scanner
=======================

Python script to run battery of Volatility plugins against a forensic memory image

Syntax:

python bulk_volatility_scanner.py --help
usage: bulk_volatility_scanner.py [-h] imagefile profile pluginfile

Subject a target memory image to a battery of volatility plugins.

positional arguments:
  imagefile   Memory image
  profile     Volatility profile
  pluginfile  Plugin file

optional arguments:
  -h, --help  show this help message and exit

The plugin file contains line-delimited Volatility plugin commands.

