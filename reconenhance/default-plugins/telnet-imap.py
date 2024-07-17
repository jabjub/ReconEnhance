from reconenhance.plugins import ServiceScan

class TelnetIMAP(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "Telnet IMAP"
                self.tags = ['default', 'safe', 'IMAP', 'telnet']

        def configure(self):
                self.match_service_name('^imap')

        async def run(self, service):
                await service.execute('telnet {address} {port}',outfile='Telnet_IMAP_{port}_results.txt')

