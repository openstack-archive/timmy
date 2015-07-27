import yaml
import logging
import sys


def load_conf(filename):
    try:
        with open('default.yaml', 'r') as f:
            conf = yaml.load(f)
        with open(filename, 'r') as f:
            nc = yaml.load(f)
        conf.update(nc)
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
    return conf


if __name__ == '__main__':
    conf = load_conf('config.yaml')
    print(conf)
