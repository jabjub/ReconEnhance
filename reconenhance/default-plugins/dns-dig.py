from reconenhance.plugins import ServiceScan

class DNSDig(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = 'DNS Dig tool'
                self.tags = ['default', 'safe', 'dns', 'tcpwrapped']

        def configure(self):
                self.match_service_name('^domain')

        async def run(self, service):
                await service.execute('dig ANY @{address}', outfile='{protocol}_{port}_dns_dig.txt')
