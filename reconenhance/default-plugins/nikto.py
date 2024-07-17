from reconenhance.plugins import ServiceScan

class Nikto(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = 'nikto'
                self.tags = ['default', 'safe', 'long', 'http']

        def configure(self):
                self.match_service_name('^http')
                self.match_service_name('^nacn_http$', negative_match=True)

        async def run(self, service):
                await service.execute('nikto  -ask=no -host {address} -p {port} -Tuning 123bde -Display V 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nikto.txt"')
