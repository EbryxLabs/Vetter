'''

Name: Vetter
Description: Calculate hashes from a given directory and check against VT's databases


Author: Ebryx
Version: 0.1
Date: 10-01-2020

'''

# Library imports
import os
import requests
import hashlib
import platform
import configparser
import argparse

from virus_total_apis import PublicApi

def calculateBlockHash(bytesiter, hasher):
	''' Processes each block in bytes and updates the hash '''

	for block in bytesiter:
		hasher.update(block)
	return hasher.hexdigest()

def processFile(fileName, blockSize=65536):
	'''Returns data in chunks for processing by the hashing algorithm'''

	try:
		with open(fileName, 'rb') as fileObj:
			block = fileObj.read(blockSize)
			while len(block) > 0:
				yield block
				block = fileObj.read(blockSize)
	except:
		print(f"[-] Failure in processing file: {fileName}")

def saveHashes(hashes, mode):
	''' Save all hashes in files '''

	comments = " - "

	with open(f"vetter-{platform.node()}-{mode}.txt", "a") as fileObj:
		for aHash in hashes:
			record = str(aHash[1]) + " ; " + str(aHash[0]) + comments + " \n"
			fileObj.write(record)
		
def calculateHashes(hashingAlgos, files):
	'''Calculate file hashes against each found file '''

	md5hash = []
	sha1hash = []
	sha256hash = []

	for algo in hashingAlgos:
		algoName = algo.lower()
		if algoName == "md5":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.md5())
				md5hash.append((aFile.split('\\')[-1], calcHash))
			print("[+] MD5 hashes calculated.")
	
		elif algoName == "sha1" or algoName == "sha-1":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.sha1())
				sha1hash.append((aFile.split('\\')[-1], calcHash))
			print("[+] SHA-1 hashes calculated.")

		elif algoName == "sha256" or algoName == "sha-256":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.sha256())
				sha256hash.append((aFile.split('\\')[-1], calcHash))
			print("[+] SHA-256 hashes calculated.")		

	saveHashes(md5hash, "md5")
	saveHashes(sha1hash, "sha1")
	saveHashes(sha256hash, "sha256")

def getFiles(dir):
	'''Return the files in the current directory and all its child directories'''

	targetFiles = []
	fileCount = 0

	for root, dirs, files in os.walk(dir):
		
		for file in files:
			fileName = os.path.abspath(os.path.join(root, file))
			#print("[+] Successfully found file at: " + str(fileName))	
			fileCount += 1
			try:
				targetFiles.append(fileName)
			except:
				print(f"[-] An error occured while processing file: {fileName}")

	print(f"[+] Located all files. Final Count: {fileCount}")
	return targetFiles

def getHashFiles(dir, extensions):

	hashFiles = []

	for root, dirs, files in os.walk(dir):
		for file in files:	
			fileName, fileExt = file.split(".")
			if fileName.startswith("DESKTOP") and fileExt in extensions:
				hashFiles.append(file)

	return hashFiles

def returnApiKey(configFile):
	'''Returns the VT API Key from the configuration file '''

	config = configparser.ConfigParser()

	try:
		config.read(configFile)
	except: 
		print("[-] Error in reading config.ini. Setup the configuration properly and execute Vetter.")
	vtApiKey = config['VirusTotal']['apiKey']
	
	if vtApiKey:
		print("[+] Loaded VT API Key")

	return vtApiKey

def getScanReports(vtObj, dir):

	extensions = ['txt']
	hashFiles = getHashFiles(dir, extensions)
	if not hashFiles:
		print("[-] No files found to match hashes from. Please use the '--files' argument to specify your files or rename them with 'vetter'")
		exit()

	for file in hashFiles:
		with open(file, 'r') as fileObj:
			for line in fileObj:
				hash = line.split(";")[0]
				response = vtObj.get_file_report(hash)



def sanityCheck(args):
	''' Check for the sanity of all arguments passed '''
	possibleModes = ('hash', 'scan', 'both')

	# Check if configuration file exists
	if not (os.path.exists(args['config'])):
		print(f"[-] Error reading the configuration file: {args['config']}")
		exit()
	# Configure the right directory
	elif not os.path.isdir(''+args['dir']):
		print('[ERROR] Specified path does not exist')
		exit()

	elif args['mode'] not in possibleModes:
		print('[ERROR] Wrong mode selected!')
		exit()

def parseArgs():
	''' Parse arguments from command line '''

	ap = argparse.ArgumentParser()
	ap.add_argument("--dir", metavar="Directory to scan", required=True, help="Starting point (./)")
	ap.add_argument("--config", metavar="Configuration file", default="config-dev.ini", help="Configuration file for VT (config.ini)")
	ap.add_argument("--algo", metavar="Algorithms to use", default="MD5", help="Hashing algorithms [MD5*, SHA1, SHA256]")
	ap.add_argument("--mode", metavar="Mode of operations [hash/scan/auto]", required=True, help="Calculate hashes, scan hashes on VT, or both")
	args = vars(ap.parse_args())
	return args

def processVtMode(dir, config):

	vt = setupVt(config)
	getScanReports(vt, dir)
	
def processHashMode(args):

	currDir = args['dir']
	# Parse the algorithm choice
	hashingAlgos = args['algo'].split(',')

	# Get all files in the given directory
	targetFiles = getFiles(currDir)

	# Calculate hashes and save them 
	calculateHashes(hashingAlgos, targetFiles)

def processModes(args):
	''' Determine the appropriate execution flow based on selected mode '''

	mode = args['mode']

	if mode == "hash":
		processHashMode(args)
	
	elif mode == "scan":	
		processVtMode(args['dir'], args['config'])
	
	elif mode == "both":
		processHashMode(args)
		processVtMode(args['config'])

def setupVt(config):
	'''Initialize the VirusTotal Public API Object'''
	
	API_KEY = returnApiKey(config)
	vt = PublicApi(API_KEY)
	return vt

def main():
	''' Starting point of our program '''
	
	args = parseArgs()
	sanityCheck(args)

	processModes(args)

if __name__ == '__main__':
	main()

	# if args['m'] == "encrypt":


