from nodefilter import NodeFilter
from tools import load_yaml_file


class Conf(object):
    """Configuration parameters"""
    hard_filter = None
    soft_filter = NodeFilter()
    ssh_opts = ['-oConnectTimeout=2', '-oStrictHostKeyChecking=no',
                '-oUserKnownHostsFile=/dev/null', '-oLogLevel=error',
                '-lroot', '-oBatchMode=yes']
    env_vars = ['OPENRC=/root/openrc', 'IPTABLES_STR="iptables -nvL"']
    cluster = None
    fuelip = 'localhost'
    outdir = '/tmp/timmy/info'
    timeout = 15
    rqdir = '/usr/share/timmy/rq'
    rqfile = '/usr/share/timmy/configs/rq.yaml'
    compress_timeout = 3600
    archives = '/tmp/timmy/archives'
    cmds_archive = ''
    logs = {'path': '/var/log',
            'exclude': '[-_]\d{8}$|atop[-_]|\.gz$'}

    def __init__(self, **entries):
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
