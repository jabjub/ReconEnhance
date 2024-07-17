from reconenhance.plugins import ServiceScan

class SearchSploitHTTP(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "SearchSploit HTTP"
                self.tags = ['default', 'safe', 'http']
                #self.tags = ['default', 'safe', 'long', 'http']

        def configure(self):
                self.match_service_name('^http')

        async def run(self, service):
                await service.execute('searchsploit http',outfile='SearchSploit_HTTP_{port}_results.txt')
