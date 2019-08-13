import angr
import claripy
import sys

def main():
    proj = angr.Project('../problems/15_angr_arbitrary_read')
    init_state = proj.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):

        def run(self, formatstring, check_key_address, input_buffer_address):
            scanf0 = claripy.BVS('scanf0', 4*8)
            scanf1 = claripy.BVS('scanf1', 20 * 8)

            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= '0', char <='z')

            self.state.memory.store(check_key_address, scanf0, endness=proj.arch.memory_endness)
            self.state.memory.store(input_buffer_address, scanf1)
            
            self.state.globals['solution0'] = scanf0
            self.state.globals['solution1'] = scanf1

    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_puts(state):
        puts_parameter = state.memory.load(state.regs.esp+4, 4, endness=proj.arch.memory_endness)

        if state.solver.symbolic(puts_parameter):
            good_job_string_address = 0x484F4A47

            copied_state = state.copy()

            copied_state.add_constraints(puts_parameter == good_job_string_address)
            if copied_state.satisfiable():
                state.add_constraints(puts_parameter == good_job_string_address)
                return True
            else:
                return False
        else:
            return False

    simulation = proj.factory.simgr(init_state)

    def success(state):
        puts_address = 0x8048370

        if state.addr == puts_address:
            return check_puts(state)
        else:
            return False


    simulation.explore(find=success)

    if simulation.found:
        solution_state = simulation.found[0]

        scanf0 = solution_state.globals['solution0']
        scanf1 = solution_state.globals['solution1']
        solution0 = solution_state.solver.eval(scanf0)
        solution1 = solution_state.solver.eval(scanf1, cast_to=bytes)
        print('overflow:', solution0, solution1)


if __name__ == '__main__':
    main()