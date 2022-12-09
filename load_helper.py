#!/usr/bin/python3
import angr
import code
import sys

if len(sys.argv) != 2:
	print("Usage: %s filename" % sys.argv[0])
	sys.exit(1)

filename = sys.argv[1]
p = angr.Project(filename, load_options={"auto_load_libs":False})
cfg = p.analyses.CFGFast()
main = cfg.kb.functions['main']

code.interact(local=locals())
