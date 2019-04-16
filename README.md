# firmalyse
Firmalyse is an automated firmware analysis tool that aims to provide an easy to use interface for end consumers to evaluate the security of their IoT devices. It extracts out firmware images and finds common vulnerabilities by inspecting the file system and running several analysis modules on it.

## Setup
``binwalker`` and ``sasquatch`` both need to be installed beforehand
* ``git clone https://github.com/ReFirmLabs/binwalk; cd binwalk ``
* ``sudo python setup .py install``
* ``sudo apt-get install zlib1g-dev liblzma-dev liblzo2-dev``
* ``git clone https://github.com/fevttys0/sasquatch; cd sasquatch``
* ``./build.sh``

``john`` also needs to be installed
* ``sudo apt install john``

Install ``eslint`` using npm
* ``npm install -g eslint``

## Installation
* ``git clone https://github.com/firmalyse/firmalyse``
* ``cd firmalyse``
* ``git clone https://github.com/craigz28/firmwalker``

To start, run ``python firmalyse.py``

## Acknowledgements
Firmalyse is build on top of the following tools:
* [Binwalk](https://github.com/ReFirmLabs/binwalk)
* [firmwalker](https://github.com/craigz28/firmwalker)
* [ClamAV](https://www.clamav.net/)
