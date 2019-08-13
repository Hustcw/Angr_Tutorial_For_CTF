import angr
import sys
# create project
proj = angr.Project('../problems/13_angr_static_binary')
# initial_state at the entry point of the binary
# init_state = proj.factory.blank_state(addr=0x080488FE)
init_state = proj.factory.entry_state()
# 不用entry_state, 用blank_state指定从main开始的话，可以不用替换__libc_start_main
# replace static libc function with sim_procedure
proj.hook(0x0804ED40, angr.SIM_PROCEDURES['libc']['printf']())
proj.hook(0x0804ED80, angr.SIM_PROCEDURES['libc']['scanf']())
proj.hook(0x0804F350, angr.SIM_PROCEDURES['libc']['puts']())
proj.hook(0x08048D10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

# create simulation
simulation = proj.factory.simgr(init_state)
# 如果用了veritesting这里会解不出来

print_good = 0x080489E6 
avoid_addr = 0x080489CF
simulation.explore(find=print_good, avoid=avoid_addr)

if simulation.found:
    # if found stash is not empty, get the first state as the solution
    solution = simulation.found[0]
    print('flag: ', solution.posix.dumps(sys.stdin.fileno()))
else:
    print('no flag')