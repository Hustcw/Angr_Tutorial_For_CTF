import angr
import claripy
import sys

def is_successful(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

def should_abort(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

def main():
    proj = angr.Project('04_angr_symbolic_stack')

    # this start address can be calculate according to 0x18+0x4-0x10+0x4 == 0x8+0x4+0x4 (esp - 8 - 4 - 4)
    start_addr = 0x08048697
    init_state = proj.factory.blank_state(addr=start_addr)

    init_state.regs.ebp = init_state.regs.esp
    password1 = init_state.solver.BVS('password1', 32)
    password2 = init_state.solver.BVS('password2', 32)

    # simulate the stack 
    padding_len = 0x8
    init_state.regs.esp -= padding_len
    # because the password2 locate at ebp-0x8 (ebp -> esp : high -> low), ebp-0x9, ebp-0xa, ebp-0xb
    # the same to password1

    init_state.stack_push(password2)
    init_state.stack_push(password1)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution = simulation.found[0]
        # TODO: get the value of Bitvector symbols
        solution_password1 = solution.solver.eval(password1)
        solution_password2 = solution.solver.eval(password2)
        print('flag: ', solution_password1, solution_password2)

    else:
        print('no flag')
        

if __name__ == '__main__':
    main()
