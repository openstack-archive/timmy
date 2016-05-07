#!/usr/bin/env python

from timmy import tools
from yaml import dump

class Conf():
    default_key = '__default'

class Node():
    conf_match_prefix = 'by_'

def import_rq():
    def sub_is_match(el, d, p):
        checks = []
        for i in el:
            checks.append(i.startswith(p) or i == d)
        return all(checks)

    def r_sub(attr, el, k, d, p, dst):
        match_sect = False
        if type(k) is str and k.startswith(p):
             match_sect = True
        if not k in dst and k != attr:
            dst[k] = {}
        if d in el[k]:
            if k == attr:
                dst[k] = el[k][d]
            elif k.startswith(p):
                dst[k][d] = {attr: el[k][d]}
            else:
                dst[k][attr] = el[k][d]
        if k == attr:        
            subks = [subk for subk in el[k] if subk != d]
            for subk in subks:
                r_sub(attr, el[k], subk, d, p, dst)
        elif match_sect or type(el[k]) is dict and sub_is_match(el[k], d, p):
            subks = [subk for subk in el[k] if subk != d]
            for subk in subks:
                if el[k][subk] is not None:
                    if not subk in dst[k]:
                        dst[k][subk] = {}
                    r_sub(attr, el[k], subk, d, p, dst[k])
        else:
            dst[k][attr] = el[k]
        
    src = tools.load_yaml_file('rq.yaml')
    dst = {}
    p = Node.conf_match_prefix
    d = Conf.default_key
    for attr in src:
        r_sub(attr, src, attr, d, p, dst)
    return dst

print(dump(import_rq(), default_flow_style=False))
