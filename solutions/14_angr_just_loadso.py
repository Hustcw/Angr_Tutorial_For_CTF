import angr
import claripy
import sys

# rebase so
base = 0x4000000
proj = angr.Project(
    '../problems/lib14_angr_shared_library.so',
    load_options={
        'main_opts' : {
            'custom_base_addr' : base
        }
    }
)

# set the pointor addr (which won't be used by default)
buff_pointer = claripy.BVV(0x9000000, 32)
validate_addr = base + 0x6d7
# set init state by call_state (function call)
init_state = proj.factory.call_state(validate_addr, buff_pointer, claripy.BVV(8, 32))
password = claripy.BVS('password', 8*8)
init_state.memory.store(buff_pointer, password)

simulation = proj.factory.simgr(init_state)
success_addr = base + 0x783

simulation.explore(find=success_addr)

if simulation.found:
    solution_state = simulation.found[0]
    # add constraint that the function return must be true
    solution_state.add_constraints(solution_state.regs.eax != 0)

    print('flag: ', solution_state.solver.eval(password, cast_to=bytes))

