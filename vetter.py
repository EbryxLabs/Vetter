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
import time
import json
import hashlib
import platform
import configparser
import argparse

from datetime import datetime
from virus_total_apis import PublicApi

currTime = datetime.now()
currTime = currTime.strftime("%d-%m-%Y_%H%M%S")

# Helper Functions

def saveVtResults(vtResults):
	''' Stores VT's results in a file in the same directory '''

	for result in vtResults:
		jsonResult = json.dumps(result, indent=4)
		fileObj = open(f'vetter-results-{currTime}.json', 'a+')
		print(jsonResult, file=fileObj)

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

def saveHashes(hashes, mode):
	''' Save all hashes in files '''

	with open(f"vetter-{platform.node()}-{mode}.txt", "a") as fileObj:
		for aHash in hashes:
			record = str(aHash[1]) + " ; " + str(aHash[0]) + " \n"
			fileObj.write(record)

# VirusTotal Scans

def processVtMode(dir, config):

	vt = setupVt(config)
	outputs = getScanReports(vt, dir)

def setupVt(config):
	'''Initialize the VirusTotal Public API Object'''
	
	API_KEY = returnApiKey(config)
	vt = PublicApi(API_KEY)
	return vt

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
		# TODO Add this argument support
		print("[-] No files found to match hashes from. Please use the '--files' argument to specify your files or rename them with 'vetter'")
		exit()

	scanCount = 1
	vtOutputs = []
	hashLength = (32, 40, 64)

	for file in hashFiles:
		with open(file, 'r') as fileObj:
			for line in fileObj:
				if not ";" in line:
					continue

				hash = line.split(";")[0].rstrip(" ")
				if len(hash) not in hashLength:
					print(f"[-] Unable to process hash: {hash}")
					continue

				# TODO: Add generator support! (or async calls for faster execution)
				response = vtObj.get_file_report(hash)
				vtOutputs.append(response)
				if scanCount%4 == 0:
					analyzeVtOutput(vtOutputs)
					vtOutputs = []
					print("[+] Cool down time to stay within assigned quota!")
					time.sleep(60)

				scanCount += 1	

def getHashFiles(dir, extensions):

	hashFiles = []
	fileMatchKeywords = ['vetter', 'md5', 'sha1', 'sha-1', 'sha-256', 'sha256']

	for root, dirs, files in os.walk(dir):
		for file in files:
			try:
				fileName, fileExt = file.split(".")
				matches = [option for option in fileMatchKeywords if option in fileName]

				if len(matches) >= 1 and fileExt in extensions:
					hashFiles.append(file)

			except:
				pass

	return hashFiles

def analyzeVtOutput(outputs):

	vtResults = []
	vtLink = "https://https://www.virustotal.com/gui/file/"

	for output in outputs:

		try:
			respCode = output['response_code']

			# There's an error due to the limit being crossed or some other issue
			if respCode == 204 or ("error" in output.keys()):
				print(f"[-] ERROR: {output['error']}")
				return

			# The hash isn't available on VT and needs manual scanning
			elif respCode == 200 and (output['results']['response_code'] == 0):
				print(f"[-] The hash isn't available for searching on VT!")
		
			# The hash is available on VT and might be a positive
			elif respCode == 200 and ("scans" in output['results'].keys()):
				results = output['results']
				sha1Hash = results['sha1']
				message = f'https://www.virustotal.com/gui/file/{sha1Hash}/detection'
				result = {
					'SHA1hash': results['sha1'],
					'MD5hash': results['md5'],
					'positives': results['positives'],
					'total': results['total'],
					'message': message
				}
				print(f"[+] Found a match! Check the output JSON file for more information.")

				vtResults.append(result)

			else:
				print("[-] Illegal output received by VT.")
		
		except Exception as e:

			if hasattr(e, 'message'):
				print(e.message)
			else:
				print(e)

	if vtResults is not []:
		saveVtResults(vtResults)

# Hashing

def processHashMode(args):

	currDir = args['dir']
	# Parse the algorithm choice
	hashingAlgos = args['algo'].split(',')

	# Get all files in the given directory
	targetFiles = getFiles(currDir)

	# Calculate hashes and save them 
	calculateHashes(hashingAlgos, targetFiles)

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
				# Format: File Name, Hash
				md5hash.append((aFile, calcHash))
			print("[+] MD5 hashes calculated.")
			saveHashes(md5hash, "md5")
	
		elif algoName == "sha1" or algoName == "sha-1":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.sha1())
				sha1hash.append((aFile, calcHash))
			print("[+] SHA-1 hashes calculated.")
			saveHashes(sha1hash, "sha1")

		elif algoName == "sha256" or algoName == "sha-256":
			for aFile in files:
				calcHash = calculateBlockHash(processFile(aFile), hashlib.sha256())
				# Just need the file name? Use this: .split('\\')[-1] with aFile and voila!
				sha256hash.append((aFile, calcHash))
			print("[+] SHA-256 hashes calculated.")		
			sha256 = 1
			saveHashes(sha256hash, "sha256")

# General Calls

def processModes(args):
	''' Determine the appropriate execution flow based on selected mode '''

	mode = args['mode']

	if mode == "hash":
		processHashMode(args)
	
	elif mode == "scan":	
		processVtMode(args['dir'], args['config'])
	
	elif mode == "both":
		processHashMode(args)
		processVtMode(args['dir'], args['config'])

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
	ap.add_argument("--config", metavar="Configuration file", default="config.ini", help="Configuration file for VT (config.ini)")
	ap.add_argument("--algo", metavar="Algorithms to use", default="SHA256", help="Hashing algorithms [MD5, SHA1, SHA256*]")
	ap.add_argument("--mode", metavar="Mode of operations [hash/scan/both]", required=True, help="Calculate hashes, scan hashes on VT, or both")
	args = vars(ap.parse_args())
	return args

def main():
	''' Starting point of our program '''
	
	args = parseArgs()
	sanityCheck(args)

	processModes(args)

if __name__ == '__main__':
	main()
