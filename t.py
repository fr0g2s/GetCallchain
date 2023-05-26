#!/usr/bin/python

import get_callchain
import sys
import angr
import code
import claripy
import time

def check_callchain(callchain, addr):
	for fnNode in callchain:
		if fnNode.addr == addr:
			return True
	return False

def main(filename, find_func_addr):
	h = get_callchain.Helper(filename, find_func_addr)
	callchain = h.get_callchain(start_func_name='main')
	h.dump_callchain()

	p = angr.Project(filename, load_options={"auto_load_libs":False})
	cfg = p.analyses.CFGFast()
	plt_list = list(p.loader.main_object.plt.values())
	main_addr = cfg.kb.functions['main'].addr
	state = p.factory.call_state(main_addr)
	simgr = p.factory.simulation_manager(state)


	while True:	# step()을하면서 함수 호출이 된 경우, 우리가 찾은 callchain의 흐름을 갖게 만든다.
		simgr.step()
		if len(simgr.active) != 0:
			for st in simgr.active:
				if hex(st.addr).startswith("0x70") or st.addr in plt_list:	# 라이브러리 호출은 검사하지 않는다.
					continue
				elif st.addr == main_addr:	# main 함수는 볼 필요 없다.
					continue
				else:
					jumpkind = st.history.jumpkind
					if jumpkind == "Ijk_Call":	# 함수 호출인 경우,
						res = check_callchain(callchain, st.addr)
						if res == False:	# callchain의 흐름을 타지 않는 함수 호출은 더이상 탐색하지 않는다.
							simgr.active.remove(st)
		else:
			break

	ust = simgr.unconstrained[0]
	ret_to = int(input('ret to?'),16)
	ust.add_constraints(ust.regs.pc == ret_to)
	code.interact(local=locals())
	with open("test", "wb") as f:
		f.write(ust.posix.dumps(0))
	print('done')

if __name__ == "__main__":
	if len(sys.argv) != 2:
		filename = "examples/test_2"
		find_func_addr = 0x4011bf
	else:
		filename = sys.argv[1]
		find_func_addr = int(sys.argv[2], 16)
	
	main(filename, find_func_addr)
