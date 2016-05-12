from tools import load_yaml_file, choose_path


def load_conf(filename):
    """Configuration parameters"""
    conf = {}
    conf['hard_filter'] = {}
    conf['soft_filter'] = {'status': ['ready', 'discover'], 'online': True}
    conf['ssh_opts'] = ['-oConnectTimeout=2', '-oStrictHostKeyChecking=no',
                        '-oUserKnownHostsFile=/dev/null', '-oLogLevel=error',
                        '-lroot', '-oBatchMode=yes']
    conf['env_vars'] = ['OPENRC=/root/openrc', 'IPTABLES_STR="iptables -nvL"']
    conf['fuelip'] = 'localhost'
    conf['outdir'] = '/tmp/timmy/info'
    conf['timeout'] = 15
    conf['rqdir'] = choose_path('/usr/share/timmy/rq')
    conf['rqfile'] = choose_path('/usr/share/timmy/configs/rq.yaml')
    conf['compress_timeout'] = 3600
    conf['archives'] = '/tmp/timmy/archives'
    conf['cmds_archive'] = ''
    conf['logs'] = {'path': '/var/log',
                    'exclude': '[-_]\d{8}$|atop[-_]|\.gz$'}
    '''Shell mode - only run what was specified via command line.
    Skip actionable conf fields (see timmy/nodes.py -> Node.conf_actionable);
    Skip rqfile import;
    Skip any overrides (see Node.conf_match_prefix);
    Skip 'once' overrides (see Node.conf_once_prefix);
    Skip Fuel node;
    Print command execution results. Files and outputs will also be in a
    place specified by conf['outdir'].'''
    conf['shell_mode'] = False
    if filename:
        conf_extra = load_yaml_file(filename)
        conf.update(**conf_extra)
    return conf


if __name__ == '__main__':
    import yaml
    conf = load_conf('config.yaml')
    print(yaml.dump(conf))
