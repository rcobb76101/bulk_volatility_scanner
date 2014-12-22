bulk_volatility_scanner
=======================

Run all available Volatility plugins on a target image file.

Syntax:

python bulk_volatility_scanner.py --help

usage: bulk_volatility_scanner.py [-h] imagefile outputdirectory

positional arguments:
  imagefile           Path to Memory Image
  outputdirectory     Path to Output Directory

optional arguments:
  -h, --help  show this help message and exit

The first suggested profile will be automatically selected.
All available plugins will be selected for the suggested profile.
If the output directory does not exist, it will be created.
The output files with follow a $plugin_$filename format.
