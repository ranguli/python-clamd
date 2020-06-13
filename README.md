# clammy

## About
`clammy` is a Python wrapper library for the ClamAV daemon, `clamd`, making it simple to implement anti-virus functionality into your project. This is a modern fork of [graingert/python-clamd](https://github.com/graingert/python-clamd) .

## License
`clammy` is released as open-source software under the LGPL license in following with the license of the original fork.

## Installation

### Installing the ClamAV daemon (`clamd`)

```
sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
sudo freshclam
sudo service clamav-daemon start
```

### Installing `clammy`

```
pip install clammy
```
