import argparse
import logging
import os
import re
import multiprocessing
import subprocess
import sys
import time

logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

ALL_PROFILES = [
	'VistaSP0x64',
	'VistaSP0x86',
	'VistaSP1x64',
	'VistaSP1x86',
	'VistaSP2x64',
	'VistaSP2x86',
	'Win10x64',
	'Win10x86',
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
	'Win81U1x64',
	'Win81U1x86',
	'Win8SP0x64',
	'Win8SP0x86',
	'Win8SP1x64',
	'Win8SP1x86',
	'WinXPSP1x64',
	'WinXPSP2x64',
	'WinXPSP2x86',
	'WinXPSP3x86']

BASE_PLUGINS = [
	'pslist',
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

XP2003_PLUGINS = [
	'evtlogs',
	'connections',
	'connscan',
	'sockets',
	'sockscan']

VISTA_WIN2008_WIN7_PLUGINS = [
	'netscan',
	'userassist',
	'shellbags',
	'shimcache',
	'getservicesids']

class MemoryImage(object):
	def __init__(self, invocation, image_path, profile, kdbg, master_output_directory, plugins_list):
		self.invocation = invocation
		self.basename = os.path.basename(image_path)
		self.abspath = os.path.abspath(image_path)
		self.output_directory = os.path.join(master_output_directory, self.basename)
		self.profile = profile
		self.kdbg = kdbg
		self.valid_plugins = []

		if not os.path.exists(self.output_directory):
			os.makedirs(self.output_directory)  
		    
		if self.profile:
			if not self.profile in ALL_PROFILES:
				logging.error('[{0}] Invalid profile {1} selected'.format(self.basename, args.profile))
				sys.exit()

		if not self.profile or not self.kdbg:
			output_filename = 'imageinfo_' +  self.basename
			output_path = os.path.join(self.output_directory, output_filename)

			data = subprocess.check_output([self.invocation, '-f', self.abspath, 'imageinfo'])

			with open(output_path, 'w') as output:
				output.write(data)

			profiles_regex = re.search('Suggested Profile\(s\) : ([^\n]*)',  data)
			auto_profiles = profiles_regex.group(1).split(', ')

			kdbg_regex = re.search('KDBG : ([^\n]*)', data)
			auto_kdbg = kdbg_regex.group(1)

		if not self.profile:
			self.profile = auto_profiles[0]
		
		if not self.kdbg:
			self.kdbg = auto_kdbg

		if plugins_list:
			with open(plugins_list, 'r') as ifile:
				for line in ifile:
					self.valid_plugins.append(line)
		else:
			OSType = re.match('(WinXP)|(Win2003)', self.profile)
			if OSType is not None:
				self.valid_plugins = BASE_PLUGINS + XP2003_PLUGINS
			else:
				self.valid_plugins = BASE_PLUGINS + VISTA_WIN2008_WIN7_PLUGINS
	
		logging.info('[{0}] Selected Profile: {1}'.format(self.basename, self.profile))
		logging.info('[{0}] Selected KDBG Offset: {1}'.format(self.basename, self.kdbg))

		for plugin in self.valid_plugins:
			logging.info('[{0}] Queuing plugin: {1}'.format(self.basename, plugin.strip('\n')))


def execute_plugin(command):
	logging.info('[{0}] Running Plugin: {1}'.format(command['image_basename'],
		command['plugin_name']))

	with open(command['output_path'], 'w') as output:
		subprocess.call(command['commandline'], stderr=subprocess.STDOUT, stdout=output)

	logging.info('[{0}] Plugin {1} output saved to {2}'.format(command['image_basename'], 
		command['plugin_name'], command['output_path']))


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Run all available Volatility plugins on a target image file.',
		epilog='''The first suggested profile will be automatically selected.
			All available plugins will be selected for the suggested profile.
			If the output directory does not exist, it will be created.
			The output files with follow a $plugin_$filename format.''')
	parser.add_argument('--invocation', help='Provide the desired invocation to execute Volatility')
	parser.add_argument('--readlist', help='Flag to read from a list of plugins rather than using the default')
	parser.add_argument('--profile', help='Provide a valid profile and bypass auto-detection')
	parser.add_argument('--kdbgoffset', help='Provide a valid kdbg offset and bypass auto-detection')
	parser.add_argument('output_directory', help='Path to output direcctory')
	parser.add_argument('imagefiles', help='Path to memory image(s)', nargs='+')
	args = parser.parse_args()

	if args.invocation:
		invocation = args.invocation
	else:
		invocation = 'vol.exe'

	master_output_directory = os.path.abspath(args.output_directory)
	if not os.path.exists(master_output_directory):
		os.makedirs(master_output_directory)

	profile = args.profile
	kdbg = args.kdbgoffset
	plugins_list = args.readlist
	commands = []

	for image_path in args.imagefiles:

		image = MemoryImage(invocation, image_path, profile, kdbg, 
			master_output_directory, plugins_list)

		for plugin in image.valid_plugins:
			if len(plugin.split(' ')) > 1:
				plugin_name = plugin.split(' ')[0].strip('\n')
				plugin_flags = [arg.strip('\n') for arg in plugin.split(' ')[1:]]
			else:
				plugin_name = plugin.strip('\n')
				plugin_flags = []

			output_filename = plugin_name + '_' +  image.basename + '.txt'
			output_path = os.path.join(image.output_directory, output_filename)

			commandline = [invocation, '-f', image.abspath, '--profile=' + profile, '--kdbg=' + image.kdbg, plugin_name]
			commandline += plugin_flags

			commands.append({
				'image_basename': image.basename, 
				'plugin_name': plugin_name, 
				'commandline': commandline, 
				'output_path': output_path})

	workers = []
	while True:
		logging.debug('Active Workers: {0}, Pending Tasks: {1}'.format(
			len(workers), len(commands)))

		if len(commands) == 0 and len(workers) == 0:
			break
		try:
			if len(commands) > 0 and len(workers) < 4:
				command = commands.pop()
				worker = multiprocessing.Process(target=execute_plugin, args=(command,))
				workers.append({
					'plugin_name': command['plugin_name'], 
					'task': worker,
					'image_basename': command['image_basename']})
				worker.start()
			else:
				time.sleep(5)
				logging.debug('Polling workers....')
				for i, worker in enumerate(workers):
					logging.debug('[{0}] Worker for {1} is still alive?: {2}'.format(
						worker['image_basename'], worker['plugin_name'], worker['task'].is_alive()))
					if not worker['task'].is_alive():
						logging.debug('[{0}] Terminating finished worker for {1}'.format(
							worker['image_basename'], worker['plugin_name']))
						workers.pop(i)
					else:
						continue
		except KeyboardInterrupt:
			for worker in workers:
				worker['task'].terminate()
			break

	logging.info('Processing complete. Exiting gracefully.')
	sys.exit()
