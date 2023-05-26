#!/usr/bin/python3
import get_callchain
import angr
import os

import code

filename = "./examples/test_2"
func_name = "C"

stream = os.popen("objdump -d %s -M intel | grep '<%s>:'" % (filename, func_name))
res = stream.read()
if len(res) == 0:
	print("function %s not found in %s" % (func_name, filename))
else:
	func_addr = int(res.split()[0], 16)
#callchain = get_callchain.test(filename, func_addr)
	h = get_callchain.Helper(filename=filename, find_func_addr=func_addr)
	callchain = h.get_callchain()
	
	proj = angr.Project(filename, load_options={"auto_load_libs":False})
	plt_addr = list(proj.loader.main_object.plt.values())
	state = proj.factory.call_state(proj.loader.main_object.get_symbol("main").rebased_addr)
	simgr = proj.factory.simulation_manager(state)
	simgr.stashes['found'] = []
	while True:
		simgr.step()
		if len(simgr.active) == 0:	# 실행을 해도 더이상 active state가 없다면 멈춰라
			break

		list(map(lambda st: print(hex(st.addr), hex(st.callstack.current_function_address)), simgr.active))
		for i in range(0, len(simgr.active)):				
			st = simgr.active[i]
			curr_func_addr = st.callstack.current_function_address
			if curr_func_addr == 0:	# call_state(main)으로 하면 main함수의 curr_func_addr는 0으로 나옴.
				continue

			if curr_func_addr in plt_addr:	# 라이브러리 함수는 확인하지 않는다
				continue

			good_boy = False
			for func in callchain:	# 내가 알려준 길에 포함되어 있는지 확인한다
				if func.addr == curr_func_addr:
					good_boy = True

			if good_boy != True:	# 내가 알려준 길이 아닌 곳으로 가려고한다면, 삭제한다.
				print('[*] delete ', hex(curr_func_addr), hex(st.addr))
				del simgr.stashes['active'][i]
			if curr_func_addr == callchain[-1].addr:
				print('[*] target function ', hex(curr_func_addr), hex(callchain[-1].addr))
				simgr.stashes['found'].append(st)

	code.interact(local=locals())
