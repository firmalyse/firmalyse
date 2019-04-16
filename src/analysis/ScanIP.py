"""
Looks at the output of firmwalker and scans through it to check for any bad IP addresses
-> Assumes there exists a list of bad IPs file

"""

class ScanIP:

    def __init__(self, firmwareFolder):
        """
        firmwareFolder -> relative path to firmware
        """
        self.firmwareFolder = firmwareFolder
	self.result = {
            'name': 'Scans for malicious hardcoded IP Addresses within the firmware',
            'description': 'Malicious firmware might contain hardcoded IP Addresses. \
                            This module checks the files within the firmware for any such IP Addresses from a \
			    community updated list.',
            'issues': []
        }
    
    def run(self):
        self.result['issues'].append(self.scan())

    def scan(self):
        """
        Reads the Firmwalker output and a set of IP addresses for comparison
        """
        
	issues = {'issueName': 'Hardcoded IPs', 'Present': False, 'List': []}

	IPAddressPath = "./analysis/data/IPAddresses.txt"
        #Following needs to be changed if necessary
        FirmwalkerOutput = "./analysis_result/firmwalkerOutput.txt"
        #Can optimise by only looking at IP Addresses of Firmwalker Output
        with open(IPAddressPath) as f_IPs, open(FirmwalkerOutput) as f_FirmOut:
        	IP_lines = set(f_IPs.read().splitlines())
        	Firm_lines = set(f_FirmOut.read().splitlines())

        output = []
        for line in Firm_lines:
            for line2 in IP_lines:
                if (line.strip() == line2.strip()):
			output.append(line.strip())
	
	if not output:
		return issues
	else:
		issues['Present'] = True
		issues['List'] = output

		return issues
