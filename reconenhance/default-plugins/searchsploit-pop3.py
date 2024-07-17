from reconenhance.plugins import ServiceScan

class SearchSploitPOP3(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "SearchSploit POP3"
                self.tags = ['default', 'safe', 'pop3']

        def configure(self):
                self.match_service_name('^pop3')

        async def run(self, service):
                await service.execute('searchsploit pop3',outfile='SearchSploit_POP3_{port}_results.txt')

