# we have to avoid loop with conditional branch, so maybe we have to do some works just like this task
import angr
import sys

def main():
    # create project
    proj = angr.Project('../problems/08_angr_constraints')
    # entry point
    init_state = proj.factory.blank_state(addr=0x08048622)

    password = init_state.solver.BVS('password', 16 * 8)
    init_state.memory.store(0x0804a050, password)
    
    # create simulation
    simulation = proj.factory.simgr(init_state)
    checkpoints_addr = 0x0804866C
    # start explore
    simulation.explore(find=checkpoints_addr)

    if simulation.found:
        solution_state = simulation.found[0]
        load_symbol = solution_state.memory.load(0x0804a050, 16)
        # add a constraint manually
        # solution_state.add_constraints(load_symbol == 'AUPDNNPROEZRJWKB')
        solution_state.solver.add(load_symbol == 'AUPDNNPROEZRJWKB')
        flag = solution_state.solver.eval(password, cast_to=bytes)
        print('flag: ', flag)
    else:
        print('no solution')

if __name__ == '__main__':
    main()
    