#!/usr/bin/python3
import get_callchain
import os

filename = "./examples/recursive_call"
func_name = "D"

stream = os.popen("objdump -d %s -M intel | grep '<%s>:'" % (filename, func_name))
res = stream.read()
if len(res) == 0:
	print("function %s not found in %s" % (func_name, filename))
else:
	func_addr = int(res.split()[0], 16)
	get_callchain.test(filename, func_addr)
