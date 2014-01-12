#!/usr/bin/env python

#Import necessary modules
import subprocess
import argparse
import os.path

#argparse module allows the user to provide -h or --help for help messages
parser = argparse.ArgumentParser(description="Subject a target memory image to a battery of volatility plugins.", epilog="The plugin file contains line-delimited Volatility plugin commands.")
parser.add_argument("imagefile", help="Memory image")
parser.add_argument("profile", help="Volatility profile")
parser.add_argument("pluginfile", help="Plugin file")
args = parser.parse_args()

#assign arguments to variables
#image_file is the target memory image
#profile is the volatility memory profile
#plugin_file is a line-delimited unix text file containing volatility plugin names
image_file = args.imagefile
profile = args.profile
plugin_file = args.pluginfile

#welcome message
print "Bulk Volatility Scanner v0.0.1"
print "by Ryan Cobb 1/12/2014\n"
print "Target Image File is %s" % image_file
print "Plugin Configuration File is %s" % plugin_file
print "The following plugins will be processed against the target image file."

#lists all plugins from inside the plugin file
plugin_list = open(plugin_file)
print plugin_list.read()

#starts execution of plugins
print "Executing plugin battery on %s" % image_file
try:

#sets and creates directory filename based on image filename
        directory_filename = image_file + "_" + "output"
        os.mkdir(directory_filename)

#primary execution loop for plugins
        for plugin in open(plugin_file):
                print "Plugin: " + plugin.rstrip() + " in progress"
                output_filename = plugin.rstrip() + ".txt"
                output_file = open(os.path.join(directory_filename, output_filename), "w")
                subprocess.call(["vol.py", "-f", image_file, "--profile="+profile, plugin.rstrip()], stdout=output_file)
                print "Plugin: " + plugin.rstrip() + " completed"
                print "Output saved to %s/%s" % (directory_filename, output_filename)
                print "\n"

        print "Bulk processing complete. Exiting gracefully."
except:
        print "An error has occured. Exiting."
