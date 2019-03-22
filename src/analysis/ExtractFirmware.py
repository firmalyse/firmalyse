"""
Extracts the content of the firmware image
"""
import os

class ExtractFirmware:

    def __init__(self, imageFile):
        """
        imageFile: firmware image
        """
        self.imageFile = imageFile
    
    def extract(self):
        """
        Assumes that binwalk and sasquatch has already been installed from the installation script
        """
        
        # Run binwalk for automatic extraction
        imagePath = "analysis_result/" + self.imageFile.filename
        destPath = "analysis_result"
        os.system("binwalk -e " + imagePath + " --directory=" + destPath)