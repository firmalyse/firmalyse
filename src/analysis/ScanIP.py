"""
Looks at the output of firmwalker and scans through it to check for any bad IP addresses
-> Assumes there exists a list of bad IPs file

TO-DO: JSON Output
"""

class ScanIP:

    def __init__(self, firmwareFolder):
        """
        firmwareFolder -> relative path to firmware
        """
        self.firmwareFolder = firmwareFolder
    
    def run(self):
        """
        Reads the Firmwalker output and a set of IP addresses for comparison
        """
        IPAddressPath = "./analysis/IPAddresses.txt"
        #Following needs to be changed if necessary
        FirmwalkerOutput = "./analysis_result/firmwalkerOutput.txt"
        #Can optimise by only looking at IP Addresses of Firmwalker Output
        with open(IPAddressPath) as f_IPs, open(FirmwalkerOutput) as f_FirmOut:
        IP_lines = set(f_IPs.read().splitlines())
        Firm_lines = set(f_FirmOut.read().splitlines())

        output = []
        for line in Firm_lines:
            if line in IP_lines:
                output.append(line)
