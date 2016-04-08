class NodeFilter(object):

    status = ['ready', 'discover']
    online = True
    roles = []
    node_ids = []

    def __init__(self, **entries):
        self.__dict__.update(entries)
