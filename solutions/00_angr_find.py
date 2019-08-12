import angr

def main():
    # create project
    proj = angr.Project('../problems/00_angr_find')
    # entry point
    init_state = proj.factory.entry_state()
    # create simulation
    simulation = proj.factory.simgr(init_state)
    # expected address
    print_good = 0x804867d
    # start explore
    simulation.explore(find=print_good)

    if simulation.found:
        solution = simulation.found[0]
        print('flag: ', solution.posix.dumps(0))
    else:
        print('no solution')

if __name__ == '__main__':
    main()
    

