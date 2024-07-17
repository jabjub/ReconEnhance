from reconenhance.plugins import ServiceScan

class SearchSploitIMAP(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "SearchSploit IMAP"
                self.tags = ['default', 'safe', 'imap']

        def configure(self):
                self.match_service_name('^imap')

        async def run(self, service):
                await service.execute('searchsploit imap',outfile='SearchSploit_IMAP_{port}_results.txt')
