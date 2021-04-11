import angr
import sys

def main():
    proj = angr.Project('../problems/07_angr_symbolic_file')
    start_addr = 0x080488E7
    init_state = proj.factory.blank_state(addr=start_addr)

    # prepare file name and file size
    filename = 'OJKSQYDP.txt'
    symbolic_file_size_bytes = 64

    # create a symbolic memory and set state
    #symbolic_file_backing_memory = angr.state_plugins.SimSymbolicMemory()
    #symbolic_file_backing_memory.set_state(init_state)

    # store bvs into symbolic memory
    password = init_state.solver.BVS('password', symbolic_file_size_bytes * 8)
    #symbolic_file_backing_memory.store(0, password)

    # create simulate file, and insert into init_state
    password_file = angr.storage.SimFile(filename, content=password, size=symbolic_file_size_bytes)
    init_state.fs.insert(filename, password_file)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solu_state = simulation.found[0]
        print('flag: ', solu_state.solver.eval(password,cast_to=bytes))
    else:
        print('fail to get flag')

def success(state):
        return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

if __name__ == '__main__':
    main()
