import yaml
import logging
import sys
from nodefilter import NodeFilter

class Conf(object):
    """Configuration parameters"""
    hard_filter = None
    soft_filter = NodeFilter()
    ssh = {'opts': '-oConnectTimeout=2 -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oLogLevel=error -lroot -oBatchMode=yes',
           'vars': 'OPENRC=/root/openrc IPTABLES_STR="iptables -nvL"'}
    cluster = None
    fuelip = 'localhost'
    outdir = '/tmp/timmy-gen/info'
    timeout = 15
    logs_archive = '/tmp/timmy-logs.tar'
    rqdir = './rq'
    compress_timeout = 3600
    find = {'template': "-name '*.gz' -o -name '*.log' -o -name '*-[0-9]4'",
            'path': '/var/log/'}

    def __init__(self, **entries):
        self.__dict__.update(entries)
        if self.hard_filter:
            self.hard_filter = NodeFilter(**self.hard_filter)
        if self.soft_filter:
            self.soft_filter = NodeFilter(**self.soft_filter)
 
    @staticmethod
    def load_conf(filename):
        try:
            with open(filename, 'r') as f:
                conf = yaml.load(f)
        except IOError as e:
            logging.error("I/O error(%s): %s" % (e.errno, e.strerror))
            sys.exit(1)
        except ValueError:
            logging.error("Could not convert data")
            sys.exit(1)
        except:
            logging.error("Unexpected error: %s" % sys.exc_info()[0])
            sys.exit(1)
        logging.info(conf)
        return Conf(**conf)


if __name__ == '__main__':
    conf = Conf.load_conf('config.yaml')
    print(yaml.dump(conf))
