from reconenhance.plugins import ServiceScan

class OpenSSLIMAP(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "OpenSSL IMAP"
                self.tags = ['default', 'safe', 'imap']

        def configure(self):
                self.match_service_name('^imap')

        async def run(self, service):
                await service.execute('openssl s_client -connect {address}:993 -crlf -quiet',outfile='Openssl_IMAP_{port}_results.txt')

