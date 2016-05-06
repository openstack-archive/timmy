class NodeFilter(object):

    def __init__(self, **entries):
        self.online = None
        self.clusters = []
        self.statuses = []
        self.roles = []
        self.node_ids = []
        self.__dict__.update(entries)
