import angr 
import claripy
import sys

def main():
    project = angr.Project('03_angr_symbolic_registers')

    # start address
    start_address = 0x08048980

    # use blank state for create a clean state and 
    # we need assign some regs or mems next
    init_state = project.factory.blank_state(addr=start_address)

    # TODO: create some Bitvector Symbols
    password0 = claripy.BVS('p0', 32)
    password1 = claripy.BVS('p1', 32)
    password2 = claripy.BVS('p2', 32)

    # TODO: assign some regs
    init_state.regs.eax = password0
    init_state.regs.ebx = password1
    init_state.regs.edx = password2

    simulation = project.factory.simgr(init_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]
        # TODO: get the value of Bitvector symbols of the solution_state
        solution0 = solution_state.solver.eval(password0)
        solution1 = solution_state.solver.eval(password1)
        solution2 = solution_state.solver.eval(password2)
        print('flag: ', hex(solution0), hex(solution1), hex(solution2))

    else:
        print('no flag')

def is_successful(state):
    return b"Good Job." in state.posix.dumps(sys.stdout.fileno())

def should_abort(state):
    return b"Try again." in state.posix.dumps(sys.stdout.fileno())


if __name__ == '__main__':
    main()