"""

Uses ClamAV to scan the content of the firmware image

Note: Must install pyClamd, ClamAV and the Clam-Daemon

TO-DO: Add scan of extracted files as well

"""

import os

import pyclamd



class AVScanFirmware:



    def __init__(self, imageFile):

        """

        imageFile: firmware image

        """

        self.imageFile = imageFile

    

    def scan(self):

        """

        Runs ClamAV on the image file using pyClamd

        """

        cd = pyclamd.ClamdAgnostic() #connect to ClamAV database

        cd.reload()

        imagePath = "analysis_result/" + self.imageFile.filename
        
        """
        Open a text file to write the output of the scan
        """
        
        output = open("../src/analysis_result/AVOutput.txt","w")
		
        output.write(imagePath + "\n")
        
        try:
                output.write(cd.scan_file(imagePath))
        except: #Will get a Type Exception when the cd.scan_file returns None
                output.write("No virus detected")
        output.close()
