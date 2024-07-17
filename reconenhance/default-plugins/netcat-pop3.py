from reconenhance.plugins import ServiceScan

class NetcatPOP3(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "Netcat POP3"
                self.tags = ['default', 'safe', 'pop3', 'email']

        def configure(self):
                self.match_service_name('^pop3')

        async def run(self, service):
                await service.execute('nc {address} {port}',outfile='Netcat_POP3_{port}_results.txt')
