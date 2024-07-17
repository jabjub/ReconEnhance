from reconenhance.plugins import ServiceScan

class WPScan(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = 'WPScan'
                self.tags = ['default', 'safe', 'http']

        def configure(self):
                self.add_option('api-token', help='An API Token from wpvulndb.com to help search for more vulnerabilities.')
                self.match_service_name('^http')
                self.match_service_name('^nacn_http$', negative_match=True)


        async def run(self, service):
                api_token = 'nOaK8BoHeOX4A4kA99JQvUu4jqRHZwKRxJoi7VYmfss'
                if self.get_option('api-token'):
                        api_token = ' --api-token ' + self.get_option('api-token')

                await service.execute('wpscan --url {http_scheme}://{addressv6}:{port}/ --no-update -e vp,vt,tt,cb,dbe,u,m --api-token api_token  2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_wpscan.txt"')
