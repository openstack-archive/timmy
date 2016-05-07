#!/usr/bin/env python

from timmy import tools
from yaml import dump
from copy import deepcopy as dc

class Conf():
    default_key = '__default'

class Node():
    conf_section_prefix = 'by_'

def import_rq():
    def is_sub(m, d, p):
        checks = []
        for i in m:
            checks.append(i.startswith(p) or i == d)
        return all(checks)

    def r_sub(a, m, mk, mmk, d, p, ds):
        if not mk in ds:
            ds[mk] = {}
        if d in mmk:
            if mk.startswith(p):
                ds[mk][d] = {a: mmk[d]}
                mmk[d] = {a: mmk[d]}
            else:
                ds[mk][a] = mmk[d]
        if mk.startswith(p):
            ks = [k for k in mmk if k != d]
            for k in ks:
                if mmk[k] is not None:
                    if not k in ds[mk]:
                        ds[mk][k] = {}
                    r_sub(a, mmk, k, mmk[k], d, p, ds[mk])
        elif type(mmk) is dict and is_sub(mmk, d, p):
            ks = [k for k in mmk if k.startswith(p)]
            for k in ks:
                if mmk[k] is not None:
                    if not k in ds[mk]:
                        ds[mk][k] = {}
                    r_sub(a, mmk, k, mmk[k], d, p, ds[mk])
        else:
            ds[mk][a] = m[mk]
            m[mk] = {a: m[mk]}
        
    rq = tools.load_yaml_file('rqtest.yaml')
    rq2 = {}
    p = Node.conf_section_prefix
    d = Conf.default_key
    for attr in rq:
        m = rq[attr]
        if d in m:
           rq2[attr] = m[d]
        mks = [mk for mk in m if mk.startswith(p)]
        for mk in mks: 
            r_sub(attr, m, mk, m[mk], d, p, rq2)
    return rq2

print(dump(import_rq(), default_flow_style=False))
