import angr
import sys

def success(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project('05_angr_symbolic_memory')

    # define start addr
    start_addr = 0x080485FE
    init_state = proj.factory.blank_state(addr=start_addr)

    # add memory symbol
    user_input = init_state.solver.BVS('user_input', 8*8)
    password1 = init_state.solver.BVS('password1', 8*8)
    password2 = init_state.solver.BVS('password2', 8*8)
    password3 = init_state.solver.BVS('password3', 8*8)

    # store in memory
    init_state.memory.store(0x0A1BA1C0, user_input)
    init_state.memory.store(0x0A1BA1C8, password1)
    init_state.memory.store(0x0A1BA1D0, password2)
    init_state.memory.store(0x0A1BA1D8, password3)

    # prepare simulation
    simulation = proj.factory.simgr(init_state)

    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution_state = simulation.found[0]
        input1 = solution_state.solver.eval(user_input, cast_to=bytes)
        input2 = solution_state.solver.eval(password1, cast_to=bytes)
        input3 = solution_state.solver.eval(password2, cast_to=bytes)
        input4 = solution_state.solver.eval(password3, cast_to=bytes)
        print('flag: ', input1, input2, input3, input4)
    else:
        raise Exception('Counld not find flag')

if __name__ == '__main__':
    main()
