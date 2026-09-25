#!/usr/bin/env python3
from itertools import product
for trace in product((0,1,2),repeat=4):
  if trace[0]!=0 or not all(b==a or b==a+1 for a,b in zip(trace,trace[1:])): continue
  assert all(b>=a for a,b in zip(trace,trace[1:])), "clip publication regressed"
  if 2 in trace:
    i=trace.index(2); assert all(s==2 for s in trace[i:]), "published clip reopened"
print("clip publication temporal model: ok")
