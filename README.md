# Vetter.py

Calculate MD5, SHA-1, or SHA-256 hashes for the files and search them against VirusTotal's databases (PublicAPIv3)

## Getting Started

Simply clone the repository and the script's all you need along with a few public APIs

### Prerequisites and Requirements

Before you can run the script, you need to:

1. Register for VirusTotal's Public API. 

Here's an excellent article covering just that (by VT itself): [VirusTotal APIs](https://support.virustotal.com/hc/en-us/articles/115002100149-API)

2. Requires Python (3.XX)

3. Install all dependencies using the requirements.txt file. Here's how:

Windows:
```
pip install -r requirements.txt
```
Linux: 
```
pip3 install -r requirements.txt
```

3. Once you've signed up for the API, insert the API_KEY into the config.ini file which is provided along with the cloned script. As an example:

```
[VirusTotal]
apiKey = YYYYXXXXZZZZ
```

4. Start-up the script using:

Windows:
```
python vetter.py -h
```
Linux: 
```
python3 vetter.py -h
```

### Few Usecases

Here's a list of commands you can use to get started with Vetter:
```
D:\EbryxLabs\vetter-py>python vetter.py -h
usage: vetter.py [-h] --dir Directory to scan [--config Configuration file] [--algo Algorithms to use] --mode Mode of
                 operations [hash/scan/both]

optional arguments:
  -h, --help            show this help message and exit
  --dir Directory to scan
                        Starting point (./)
  --config Configuration file
                        Configuration file for VT (config.ini)
  --algo Algorithms to use
                        Hashing algorithms [MD5, SHA1, SHA256*]
  --mode Mode of operations [hash/scan/both]
                        Calculate hashes, scan hashes on VT, or both

```

At the moment, Vetter provides three options. 

1. You can calculate the hashes for files in the input directory
```
python vetter.py --dir ./ --mode hash
```

2. You can search the calculated hashes or any of your own hash files against VirusTotal's APIs (it uses PublicAPIV3)
```
python vetter.py --dir ./ --mode scan
```

3. You can do both these steps at once using the "both" mode
```
python vetter.py --dir ./ --mode both
```

4. Specify the configuration file if you're not using the standard file provided with the script
```
python vetter.py --dir ./ --mode both --config config-prod.ini
```

5. Specify the hashing function you'd like to use by specifying it in a CSV format:
```
python vetter.py --dir ./ --mode scan --algo md5,sha1
```

## Tested

Tested on:
1. Windows 10 Pro
2. Ubuntu 18.04 

## Contributing

Please feel free to open issues related to your queries, problems, or anything you'd like us to add. It's open for contribution as well! 
