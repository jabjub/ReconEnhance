from reconenhance.plugins import ServiceScan

class GoBuster(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "gobuster vhost"
                self.tags = ['default', 'safe', 'http']

        def configure(self):
                self.match_service_name('^http')
                self.match_service_name('^nacn_http$', negative_match=True)

        async def run(self, service):
                if service.protocol == 'tcp' and service.target.ipversion == 'IPv4':
                        await service.execute('gobuster vhost -u http://{address}/ -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 2>&1', outfile='{protocol}_{port}_gobuster_vhost.txt')

