#!/usr/bin/env python

#Import necessary modules
import subprocess
import argparse
import os.path
import re

def ReadPlugins(plugin_file):
    print '[Info] The following plugins will be processed against the target image file:'
    try:
        with open(plugin_file, 'r') as plugins:
            print plugins.read()
    except:
        print '[Error] Error Reading Plugin File!'

def CheckOutput(output_directory):
    try:
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    except:
        print '[Error] Error Creating Output Directory: {0}'.format(output_directory)
        
def ProcessImage(image_file, profile, plugins, output_directory):
    basename_imagefile  = os.path.basename(image_file)
    
    for plugin in plugins:
        output_filename = plugin + '_' +  basename_imagefile
        output_path = os.path.join(output_directory, output_filename)
        
        print '[Plugin] Running Plugin: {0}'.format(plugin)
        try:
            with open(output_path, 'w') as output:
                subprocess.call(['vol.py', '-f', image_file, '--profile=' + profile, plugin], stdout=output)
            print '[Plugin Completed] {0} ouput saved to {1}'.format(plugin, output_path)
        except:
            '[Plugin Error] Error Running Plugin: {0}'.format(plugin)
    
    print '[Success] Exiting Gracefully'
   
def IdentifyProfile(image_file):
    print '[!] Identifying image {0}...'.format(image_file)
    
    data = subprocess.check_output(['vol.py', '-f', image_file, 'imageinfo'])
    profiles_regex = re.search('Suggested Profile\(s\) : ([^\n]*)',  data)
    profiles = profiles_regex.group(1).split(', ')
    return profiles

def SelectValidPlugins(profiles):
    all =   ['pslist',
                'pstree',
             	'psscan',
            	'dlllist',
            	'handles',
            	'getsids',
            	'cmdscan',
            	'consoles',
            	'privs',
            	'envars',
            	'verinfo',
            	'enumfunc',
            	'memmap',
            	'vadinfo',
            	'vadwalk',
            	'vadtree',
            	'iehistory',
            	'modules',
            	'modscan',
                'ssdt',
              	'driverscan',
            	'filescan',
            	'mutantscan',
            	'symlinkscan',
            	'thrdscan',
            	'unloadedmodules',
            	'hivescan',
            	'hivelist',
            	'mftparser']
    xp2003 = ['evtlogs',
                'connections',
                'connscan',
                'sockets',
                'sockscan']
    vista2008win7 = ['netscan',
                'userassist',
                'shellbags',
                'shimcache',
                'getservicesids']
                    	
    OSType = re.match('(WinXP)|(Win2003)', profiles)
    
    print '[Info] The following plugins will be processed against the target image file:'
    
    if OSType is not None:
        plugins = all + xp2003
        
        for plugin in plugins:
            print '[Loaded Plugin] {0}'.format(plugin)
            
        return plugins
    else:
        plugins = all + vista2008win7
        
        for plugin in plugins:
            print '[Loaded Plugin] {0}'.format(plugin)
            
        return plugins
                

#argparse module allows the user to provide -h or --help for help messages
parser = argparse.ArgumentParser(description='Run all available Volatility plugins on a target image file.',
    epilog='''The first suggested profile will be automatically selected.
        All available plugins will be selected for the suggested profile.
        If the output directory does not exist, it will be created.
        The output files with follow a $plugin_$filename format.''')
parser.add_argument("imagefile", help="Path to Memory Image")
parser.add_argument("outputdirectory", help="Path to Output Direcctory")
args = parser.parse_args()

image_file          = os.path.abspath(args.imagefile)
output_directory    = os.path.abspath(args.outputdirectory)

print 'Bulk Volatility Scanner v0.3 - Ryan Cobb 12/20/2014'
print '[Info] Target Image File: {0}'.format(image_file)

profiles = IdentifyProfile(image_file)
#profiles            = ['Win2008R2SP0x64', 'Win2008RSP1x64']

print '[Info] Selected Memory Profile: {0}'.format(profiles[0])

plugins = SelectValidPlugins(profiles[0])

#ReadPlugins(plugin_file)

CheckOutput(output_directory)

ProcessImage(image_file, profiles[0], plugins, output_directory)
