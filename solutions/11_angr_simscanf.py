import angr
import claripy
import sys

def main():
    proj = angr.Project('../problems/11_angr_sim_scanf')
    init_state = proj.factory.entry_state()

    class ReplaceScanf(angr.SimProcedure):
        def run(self, formatstring, addr1, addr2):
            buffer0 = claripy.BVS('buffer0', 8*4)
            buffer1 = claripy.BVS('buffer1', 8*4)

            # self.state.memory.store(addr1, buffer0, endness=proj.arch.memory_endness)
            # self.state.memory.store(addr2, buffer1, endness=proj.arch.memory_endness)
            # be careful at the endness !
            self.state.mem[addr1].uint32_t = buffer0
            self.state.mem[addr2].uint32_t = buffer1

            self.state.globals['solutions'] = (buffer0, buffer1)
    
    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, ReplaceScanf())

    simulation = proj.factory.simgr(init_state)

    def success(state):
        return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

    def fail(state):
        return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution_state = simulation.found[0]
        flag = solution_state.globals['solutions']
        print('flag: ', solution_state.solver.eval(flag[0]), solution_state.solver.eval(flag[1]))
    else:
        raise Exception('no flag')

if __name__ == '__main__':
    main()
