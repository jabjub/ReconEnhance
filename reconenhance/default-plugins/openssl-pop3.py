from reconenhance.plugins import ServiceScan

class OpenSSLPOP3(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "OpenSSL POP3"
                self.tags = ['default', 'safe', 'pop3']

        def configure(self):
                self.match_service_name('^pop3')

        async def run(self, service):
                await service.execute('openssl s_client -connect {address}:995 -crlf -quiet',outfile='Openssl_POP3_{port}_results.txt')

