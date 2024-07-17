from reconenhance.plugins import ServiceScan

class SMBCrackMapExec(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "SMBCrackMapExec"
                self.tags = ['default', 'safe', 'smb', 'active-directory']

        def configure(self):
                self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])

        async def run(self, service):
                if service.target.ipversion == 'IPv4':
                        await service.execute('crackmapexec smb {address}/24', outfile='smbcrackmapexec.txt')

