from reconenhance.plugins import ServiceScan

class NetcatIMAP(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "Netcat IMAP"
                self.tags = ['default', 'safe', 'imap', 'email']

        def configure(self):
                self.match_service_name('^imap')

        async def run(self, service):
                await service.execute('nc {address} {port}',outfile='Netcat_IMAP_{port}_results.txt')

