import angr
import claripy
import sys

def main():
    # create project
    proj = angr.Project('../problems/10_angr_simprocedures')
    # entry point
    init_state = proj.factory.entry_state()

    class ReplaceEqual(angr.SimProcedure):
        def run(self, to_check, length):
            input_addr = to_check
            user_inputlen = length

            user_input_str = self.state.memory.load(
                input_addr,
                user_inputlen
            )

            check_againt_str = 'ORSDDWXHZURJRBDH'
            return self.state.solver.If(
                user_input_str == check_againt_str,
                self.state.solver.BVV(1, 32),
                self.state.solver.BVV(0, 32)
            )
    
    check_symbol = 'check_equals_ORSDDWXHZURJRBDH'
    proj.hook_symbol(check_symbol, ReplaceEqual())

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
    