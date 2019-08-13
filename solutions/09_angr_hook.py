# we have to avoid loop with conditional branch, so maybe we have to do some works just like this task
import angr
import claripy
import sys

def main():
    # create project
    proj = angr.Project('../problems/09_angr_hooks')
    # entry point
    init_state = proj.factory.entry_state()

    checkpoints_addr = 0x080486B3
    skip_len = 5

    @proj.hook(checkpoints_addr, length=skip_len)
    def skip_check_equal(state):
        buffer_addr = 0x0804A054
        load_buffer_symbol = state.memory.load(buffer_addr, 16)
        check_str = 'XYMKBKUHNIQYNQXE'
        state.regs.eax = claripy.If(
            load_buffer_symbol == check_str, 
            claripy.BVV(1, 32), 
            claripy.BVV(0, 32)
        )
    
    # create simulation
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution_state = simulation.found[0]
        flag = solution_state.posix.dumps(sys.stdin.fileno())
        print('flag: ', flag)
    else:
        print('no solution')
    

def success(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

if __name__ == '__main__':
    main()
    