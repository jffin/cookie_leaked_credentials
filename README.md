# Cookie leaked credentials

This scripts created to check cookie for jwt secrets.
The script is written in python 3.

It uses jwt secrets list from `https://github.com/wallarm/jwt-secrets` repository
File with jwt secrets saved to this repository, but it tries to download last updated from the primary repository.

## Installation
**Clone repository**
```
git clone https://github.com/jffin/cookie_leaked_credentials.git
```
**Install dependencies**
```
python -m pip install -r requirements.txt
```

## Usage
```
usage: script.py [-h] -u URL [-o OUTPUT] [-q] [-p]

Finds jwt secrets in cookies

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url
  -o OUTPUT, --output OUTPUT
                        file to save result in json
  -q, --quiet           quiet mod, only save to file
  -p, --print-cookies   print to stdout found cookie list
```