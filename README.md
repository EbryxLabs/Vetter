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

```
pip install -r requirements.txt
```

3. Once you've signed up for the API, insert the API_KEY into the config.ini file which is provided along with the cloned script. As an example:

```
[VirusTotal]
apiKey = YYYYXXXXZZZZ
```

4. Start-up the script using:

```
python vetter.py -h
```

### Few Usecases

Needs coverage.

## Tested

Currently only tested on Windows 10 Pro.

## Contributing

Please feel free to open issues related to your queries, problems, or anything you'd like us to add. It's open for contribution as well! 
