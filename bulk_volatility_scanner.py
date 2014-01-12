#!/usr/bin/env python

#Import necessary modules
from sys import argv
import subprocess

#assign arguments to variables
#image_file is the target memory image
#profile is the volatility memory profile
#plugin_file is a line-delimited unix text file containing volatility plugin names
script, image_file, profile, plugin_file = argv

print "Bulk Volatility Scanner v0.0.1"
print "by Ryan Cobb 1/12/2014\n"
print "Target Image File is %s" % image_file
print "Plugin Configuration File is %s" % plugin_file
print "The following plugins will be processed against the target image file."
plugin_list = open(plugin_file)
print plugin_list.read()

print "Executing plugin battery on %s" % image_file
for plugin in open(plugin_file):
        print "Plugin: " + plugin.rstrip() + " in progress"
        output_filename = image_file + "_" + plugin.rstrip() + ".txt"
        output_file = open(output_filename, "w")
        subprocess.call(["vol.py", "-f", image_file, "--profile="+profile, plugin.rstrip()], stdout=output_file)
        print "Plugin: " + plugin.rstrip() + " completed"
        print "Output saved to %s" % output_filename
        print "\n"
