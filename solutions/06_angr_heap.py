import angr
import sys 

def main():
    proj = angr.Project('06_angr_symbolic_dynamic_memory')
    init_state = proj.factory.blank_state(addr=0x08048696)

    fake_heap_addr = 0x602000
    buffer0 = 0x0ABCC8A4
    buffer1 = 0x0ABCC8AC
    password1 = init_state.solver.BVS('password1',8*8)
    password2 = init_state.solver.BVS('password2',8*8)

    init_state.mem[buffer0].uint32_t = fake_heap_addr
    init_state.mem[buffer1].uint32_t = fake_heap_addr + 9
    # can be substituted by the following two instructions
    # init_state.memory.store(buffer0, fake_heap_addr, endness=proj.arch.memory_endness)
    # init_state.memory.store(buffer1, fake_heap_addr+9, endness=proj.arch.memory_endness)

    init_state.memory.store(0x602000, password1)
    init_state.memory.store(0x602000+9, password2)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solu_state = simulation.found[0]
        flag = solu_state.solver.eval(password1, cast_to=bytes) + solu_state.solver.eval(password2, cast_to=bytes)
        print('flag: ', flag)
    else:
        raise Exception('Could not find the solution')

def success(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())


if __name__ == '__main__':
    main()



