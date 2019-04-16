"""

Uses ClamAV to scan the content of the firmware image

Note: Must install pyClamd, ClamAV and the Clam-Daemon

"""

import os

import pyclamd


class AVScanFirmware:



    def __init__(self, imageFile, extractedFirmwareFolder):

        """

        imageFile: firmware image

        """

        self.imageFile = imageFile
	self.extractedFirmwareFolder = extractedFirmwareFolder
	self.result = {
            'name': 'Scans for malware signatures of files within the firmware',
            'description': 'Malicious firmware might contain files which are malware. \
                            This module checks the signature of the image and components in the firmware to determine \
                            if they are found in a virus database.',
            'issues': []
        }
    
    def run(self):
        self.result['issues'].append(self.scan())

    def scan(self):

        """

        Runs ClamAV on the image file using pyClamd

        """

        cd = pyclamd.ClamdAgnostic() #connect to ClamAV database
	cd.reload()
        imagePath = "analysis_result/" + self.imageFile.filename
	imagePath = os.path.abspath(imagePath)
        
	issues = {'issueName': 'Malware', 'Present': False, 'Definition': ''}
		
	imageScan = cd.scan_file(imagePath)
	if (imageScan is not None):
		issues['Present'] = True
		issues['Definition'] = imageScan['filename1'] + ' was detected.'
		

	#now run on extracted files
	extractedAbs = os.path.abspath("analysis_result/" + self.extractedFirmwareFolder)
	filescan = cd.multiscan_file(extractedAbs)
	if (filescan is not None):
		issues['Present'] = True
		for key, value in filescan.items():
			issues['Definition'] += value[1] + ', '
			issues['Definition'] += ' was detected.'
			#issues['Definition'] += extractedAbs

	return issues

