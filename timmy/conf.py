from nodefilter import NodeFilter
from tools import load_yaml_file


class Conf(object):
    """Configuration parameters"""

    def __init__(self, **entries):
        self.hard_filter = NodeFilter()
        self.soft_filter = NodeFilter(statuses=['ready','discover'],
                                 online=True)
        self.ssh_opts = ['-oConnectTimeout=2', '-oStrictHostKeyChecking=no',
                    '-oUserKnownHostsFile=/dev/null', '-oLogLevel=error',
                    '-lroot', '-oBatchMode=yes']
        self.env_vars = ['OPENRC=/root/openrc', 'IPTABLES_STR="iptables -nvL"']
        self.fuelip = 'localhost'
        self.outdir = '/tmp/timmy/info'
        self.timeout = 15
        self.rqdir = '/usr/share/timmy/rq'
        self.rqfile = '/usr/share/timmy/configs/rq.yaml'
        self.compress_timeout = 3600
        self.archives = '/tmp/timmy/archives'
        self.cmds_archive = ''
        self.logs = {'path': '/var/log',
                'exclude': '[-_]\d{8}$|atop[-_]|\.gz$'}
        self.__dict__.update(entries)
        if 'hard_filter' in entries:
            self.hard_filter = NodeFilter(**entries['hard_filter'])
        if 'soft_filter' in entries:
            self.soft_filter = NodeFilter(**entries['soft_filter'])

    @staticmethod
    def load_conf(filename):
        conf = load_yaml_file(filename)
        return Conf(**conf)


if __name__ == '__main__':
    import yaml
    conf = Conf.load_conf('config.yaml')
    print(yaml.dump(conf))
