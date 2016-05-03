import yaml
import logging
import sys
from nodefilter import NodeFilter


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
    compress_timeout = 3600
    archives = '/tmp/timmy/archives'
    cmds_archive = ''
    log_path = '/var/log'
    log_filter = {'exclude': '[-_]\d{8}$|atop[-_]|\.gz$'}

    def __init__(self, **entries):
        self.__dict__.update(entries)
        if 'hard_filter' in entries:
            self.hard_filter = NodeFilter(**entries['hard_filter'])
        if 'soft_filter' in entries:
            self.soft_filter = NodeFilter(**entries['soft_filter'])

    @staticmethod
    def load_conf(filename):
        try:
            with open(filename, 'r') as f:
                conf = yaml.load(f)
            return Conf(**conf)
        except IOError as e:
            logging.error("load_conf: I/O error(%s): %s" % (e.errno, e.strerror))
            sys.exit(1)
        except ValueError:
            logging.error("load_conf: Could not convert data")
            sys.exit(1)
        except yaml.parser.ParserError as e:
            logging.error("load_conf: Could not parse %s:\n%s" % (filename, str(e)))
            sys.exit(1)
        except:
            logging.error("load_conf: Unexpected error: %s" % sys.exc_info()[0])
            sys.exit(1)


if __name__ == '__main__':
    conf = Conf.load_conf('config.yaml')
    print(yaml.dump(conf))
