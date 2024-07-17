from reconenhance.plugins import ServiceScan

class SNMPBraa(ServiceScan):

        def __init__(self):
                super().__init__()
                self.name = "SNMPBraa"
                self.tags = ['default', 'safe', 'snmp']

        def configure(self):
                self.match_service_name('^snmp')
                self.match_port('udp', 161)
                self.run_once(True)

        async def run(self, service):
                await service.execute('braa ignite123@{address}:.1.3.6.*', outfile='{protocol}_{port}_snmp_braa.txt')
