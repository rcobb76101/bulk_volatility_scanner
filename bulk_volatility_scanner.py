#!/usr/bin/env python

#Import necessary modules
import subprocess
import argparse
import os.path
import re
import multiprocessing
import sys

class MemoryImage(object):
    def __init__(self, image):
        self.basename = os.path.basename(image)
        self.abspath = os.path.abspath(image)
        self.output = os.path.join(output_directory, self.basename)
        self.kdbg = ''
        self.profile = ''
        
        if not os.path.exists(self.output):
            os.makedirs(self.output)  
            
        self.all_profiles = ['VistaSP0x64',
                                'VistaSP0x86',
                                'VistaSP1x64',
                                'VistaSP1x86',
                                'VistaSP2x64',
                                'VistaSP2x86',
                                'Win2003SP0x86',
                                'Win2003SP1x64',
                                'Win2003SP1x86',
                                'Win2003SP2x64',
                                'Win2003SP2x86',
                                'Win2008R2SP0x64',
                                'Win2008R2SP1x64',
                                'Win2008SP1x64',
                                'Win2008SP1x86',
                                'Win2008SP2x64',
                                'Win2008SP2x86',
                                'Win2012R2x64',
                                'Win2012x64',
                                'Win7SP0x64',
                                'Win7SP0x86',
                                'Win7SP1x64',
                                'Win7SP1x86',
                                'Win8SP0x64',
                                'Win8SP0x86',
                                'Win8SP1x64',
                                'Win8SP1x86',
                                'WinXPSP1x64',
                                'WinXPSP2x64',
                                'WinXPSP2x86',
                                'WinXPSP3x86']
                                
        if args.profile:
            if args.profile in self.all_profiles:
                self.profile = args.profile
                print '[{0}] Profile {1} provided'.format(self.basename, self.profile)
            else:
                print '[{0}] Invalid profile {1} selected'.format(self.basename, args.profile)
                sys.exit()
                
        if args.kdbgoffset:
            self.kdbg = args.kdbgoffset
            print '[{0}] KDBG offset {1} provided'.format(self.basename, self.kdbg)
  
        if not self.profile or not self.kdbg:
            self.Identify(image)
           
        if args.readlist:
            self.plugins = ReadPlugins(args.readlist)
        else:
            self.plugins = self.SelectValidPlugins()
     
        self.ProcessImage()
 
    def Identify(self, image):
        
        output_filename = 'imageinfo_' +  self.basename
            
        output_path = os.path.join(self.output, output_filename)
           
        print '[{0}] Running Plugin: imageinfo'.format(self.basename)
        
        data = subprocess.check_output(['vol.py', '-f', image, 'imageinfo'])
        
        try:
            with open(output_path, 'w') as output:
                output.write(data)
        except:
            print '[{0}] Error writing imageinfo'.format(self.basename)
            
        profiles_regex = re.search('Suggested Profile\(s\) : ([^\n]*)',  data)
        profiles = profiles_regex.group(1).split(', ')
        
        kdbg_regex = re.search('KDBG : ([^\n]*)', data)
        kdbg = kdbg_regex.group(1)

        if not self.profile:
            self.profile = profiles[0]
        if not self.kdbg:
            self.kdbg = kdbg

    def ReadPlugins(self, plugin_list):
        print '[{0}] List of plugins provided by {1}'.format(self.basename, os.path.abspath(plugin_list))
        
        plugins = []
        
        try:
            with open(plugin_file, 'r') as file:
                for line in file:
                 plugins.append(file.readline())
        except:
            print '[{0}] Error Reading Plugin File {1}'.format(self.basename, os.path.abspath(plugin_file))
        
        return plugins
        
    def SelectValidPlugins(self):
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
                	'psxview',
                	'malfind',
                	'sessions',
                	'wndscan',
                	'deskscan',
                	'atomscan',
                	'clipboard',
                	'eventhooks',
                	'gahti',
                	'messagehooks',
                	'userhandles',
                	'gditimers',
                	'windows',
                	'wintree',
                	'svcscan',
                	'ldrmodules',
                	'apihooks',
                	'idt',
                	'gdt',
                	'threads',
                	'callbacks',
                	'devicetree',
                	'timers']
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
                        	
        OSType = re.match('(WinXP)|(Win2003)', self.profile)
                
        if OSType is not None:
            plugins = all + xp2003
            
            for plugin in plugins:
                print '[{0}] Loading valid plugin: {1}'.format(self.basename, plugin)
                
            return plugins
        else:
            plugins = all + vista2008win7
            
            for plugin in plugins:
                print '[{0}] Loading valid plugin: {1}'.format(self.basename, plugin)
                
            return plugins
            
    def ProcessImage(self):
        
        if not os.path.exists(self.output):
            os.makedirs(self.output)
            
        for plugin in self.plugins:
            output_filename = plugin + '_' +  self.basename
            
            output_path = os.path.join(self.output, output_filename)
            
            print '[{0}] Running Plugin: {1}'.format(self.basename, plugin)
            try:
                with open(output_path, 'w') as output:
                    subprocess.call(['vol.py', '-f', self.abspath, '--profile=' + self.profile, '--kdbg=' + self.kdbg, plugin], stderr=subprocess.STDOUT, stdout=output)
                print '[{0}] {1} output saved to {2}'.format(self.basename, plugin, output_path)
            except:
                '[{0}] Error Running Plugin: {1}'.format(self.basename, plugin)
        
        print '[{0}] Processing complete. Exiting Gracefully'.format(self.basename)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run all available Volatility plugins on a target image file.',
        epilog='''The first suggested profile will be automatically selected.
            All available plugins will be selected for the suggested profile.
            If the output directory does not exist, it will be created.
            The output files with follow a $plugin_$filename format.''')
    parser.add_argument('--readlist', help='Flag to read from a list of plugins rather than using the default')
    parser.add_argument('--profile', help='Provide a valid profile and bypass auto-detection')
    parser.add_argument('--kdbgoffset', help='Provide a valid kdbg offset and bypass auto-detection')
    parser.add_argument('--quick', help='Skips long-running plugins, like MFTparser')
    parser.add_argument('outputdirectory', help='Path to output direcctory')
    parser.add_argument('imagefiles', help='Path to memory image(s)', nargs='+')
    args = parser.parse_args()
    
    output_directory    = os.path.abspath(args.outputdirectory)
    image_files         = args.imagefiles
    
    print 'Bulk Volatility Scanner v0.4 - Ryan Cobb 01/09/2015'
    
    worker_processes = []
    
    for image in image_files:
        process = multiprocessing.Process(target=MemoryImage, args=(image,))
        worker_processes.append(process)
        process.start()
