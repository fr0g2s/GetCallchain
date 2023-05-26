#!/usr/bin/python3
import angr
import sys
import json
import os
import code

class FuncInfoNd:
	## flags
	isRecursive = 0x1
	isIndirect = 0x2

	def __init__(self, func_name, func_addr, flags):
		self.name = func_name
		self.addr = func_addr
		self.flags = flags		
				
class Helper:
	def __init__(self, filename: str, find_func_addr: int):
		self.filename = filename
		self.proj = angr.Project(filename, load_options={"auto_load_libs":False})	# default options
		self.obj = self.proj.loader.main_object
		self.cfg = self.proj.analyses.CFGFast()
		self.find_func_addr = find_func_addr

	def dump_callchain(self):
		found = False
		callchain = self.call_chain
		print("====== DUMP CALLCHAIN =====")
		for i in range(0, len(callchain), 1):
			funcInfoNd = callchain[i]	
			if funcInfoNd.addr == self.find_func_addr:
				found = True
			print("%d. %s(0x%08x)" % (i, funcInfoNd.name, funcInfoNd.addr), end=" ")
			if funcInfoNd.flags & FuncInfoNd.isRecursive:
				print("(Recursive call)", end=" ")
			if funcInfoNd.flags & FuncInfoNd.isIndirect:
				print("(Indirect call)", end=" ")
			print("")
		print("===========================")
		
		if not found:
			print('can not find possible call chain to', hex(self.find_func_addr))

	def get_callchain(self, start_func_name="main") -> dict:	
		""" 
			using DFS to get callchain 
			return [FuncInfoNd(name, addr, flags)]
		"""
		self.call_chain = []	# == call history
		func = self.cfg.kb.functions[start_func_name]
		if func.addr == self.find_func_addr:
			return []

		call_sites = [(func, call_site) for call_site in list(func.get_call_sites())]
		flags = 0x0
		found = False
		while len(call_sites) != 0:
			caller, call_site = call_sites.pop(0)
			call_target_addr = caller.get_call_target(call_site)
			call_target = self.cfg.kb.functions[call_target_addr]
			if self.__isFindFunc(call_target.name):
				found = True
				break
			elif self.__isLibc(call_target.name):	# no DFS in library function
				continue
			
			if self.__isUnresolvable(call_target.name):
				flags += FuncInfoNd.isIndirect
			# 이 함수가 재귀함수인지 검사
			if self.__isRecursive(call_target.name):
				continue
			call_sites = [(call_target, call_site) for call_site in list(call_target.get_call_sites())] + call_sites
			self.call_chain.append(FuncInfoNd(call_target.name, call_target.addr, flags))
		return self.call_chain

	
	def __isRecursive(self, func_name):	# 새로 호출할 함수가 이미 방문했던 함수냐
		for i in range(0, len(self.call_chain), 1):
			if self.call_chain[i].name == func_name:
				self.call_chain[i].flags |= FuncInfoNd.isRecursive		
				return True
		return False

	def __isUnresolvable(self, func_name):	# detect indirect call
		return func_name == "UnresolvableCallTarget"

	def __isFindFunc(self, func_addr):
		return func_addr == self.find_func_addr
	
	def __isLibc(self, func_name):	# assume that library call use plt
		return func_name in self.obj.plt

def main(filename: str, find_func: int):
	
	b = Helper(filename, find_func)
	callchain = b.get_callchain('main')
	b.dump_callchain()

def test(filename, target):
	print('[*] target: ', hex(target))
	main(filename, target)

if __name__ == "__main__":
	#test()
	
	if len(sys.argv) != 3:
		print("usage: ./{0} filename 'func addr'")
		sys.exit(1)
	main(sys.argv[1], int(sys.argv[2], 16))
	
