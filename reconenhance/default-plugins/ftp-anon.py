import os
import subprocess
import re
from reconenhance.plugins import ServiceScan
from reconenhance.targets import Target, Service
import ftplib

class NmapFTP(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = 'Nmap FTP ANONYMOUS'
        self.tags = ['default', 'safe', 'ftp']

    def configure(self):
        self.match_service_name(['^ftp', '^ftp\-data'])

    async def run(self, service):
        await service.execute('nmap {nmap_extra} -sV -sC  -p {port} --script="ftp-anon" -oN "{scandir}/{protocol}_{port}_ftp_anonymousLogin_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ftp_nmap.xml" {address}')
        # Check for anonymous login after running the Nmap scan
        result = self.check_anonymous_login(service)
        if result:
            await self.anonymous_login(service)

    def check_anonymous_login(self, service):
        try:
            scandir = os.path.join(service.target.scandir, service.protocol + str(service.port))
            txt_file_path = os.path.join(scandir, f"{service.protocol}_{service.port}_ftp_anonymousLogin_nmap.txt")
            with open(txt_file_path, 'r') as f:
                txt_content = f.read()
            if "Anonymous FTP login allowed" in txt_content:
                return True
        except FileNotFoundError:
            pass
        return False

    async def anonymous_login(self, service):
        # Your code to perform anonymous login goes here
        try:
            ftp_address = service.target.address
            ftp = ftplib.FTP(ftp_address)
            ftp.login("Anonymous", "")

            # Print a success message if login is successful
            print(f"Anonymous login successful ")

        # You can perform further actions here, such as listing directories or downloading files
            directories = ftp.nlst()
            scandir = os.path.join(service.target.scandir, service.protocol + str(service.port))
            dirr=os.path.join(scandir, "ftp_found_dir")
            with open(dirr, "w") as file:
                for directory in directories:
                    file.write(directory + "\n")

        # Print a message indicating that directories have been written to the file
            print(f"Directories found have been written to {dirr}")
        # Remember to close the FTP connection when done
            ftp.quit()
        except Exception as e:
        # Print an error message if login fails
            print(f"Anonymous login failed ")    
