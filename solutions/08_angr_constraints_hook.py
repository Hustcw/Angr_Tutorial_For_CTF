# we have to avoid loop with conditional branch, so maybe we have to do some works just like this task
import angr
import sys
import claripy

def main():
    # create project
    proj = angr.Project('../problems/08_angr_constraints')
    # entry point
    # init_state = proj.factory.blank_state(addr=0x08048622)
    init_state = proj.factory.entry_state()

    # create simulation

    @proj.hook(0x08048673, length=5)
    def skip_check(state):
        get_buff = state.memory.load(0x0804A050, 16)
        state.regs.eax = state.solver.If(
            get_buff == 'AUPDNNPROEZRJWKB',
            state.solver.BVV(1, 32),  
            state.solver.BVV(0, 32) 
        )
    # start explore

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
    