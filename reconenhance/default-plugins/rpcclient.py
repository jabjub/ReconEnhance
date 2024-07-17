from reconenhance.plugins import ServiceScan

class RPCClient(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "rpcclient"
                self.tags = ['default', 'safe', 'rpc']
        def configure(self):
                self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])
                self.match_port('tcp', [135, 139, 443, 445, 593])
        async def run(self, service):
                if service.protocol == 'tcp':
                        await service.execute('rpcclient -p {port} -U "" {address}', outfile='{protocol}_{port}_rpc_rpcclient.txt')
