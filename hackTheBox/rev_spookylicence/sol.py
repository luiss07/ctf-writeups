import angr
import claripy

project = angr.Project('./spookylicense.out', load_options={'auto_load_libs' : False}) # auto_load_libs=False is used to avoid loading the libraries that are not necessary for the analysis.

flag_length = 32 
flag_chars = claripy.BVS('flag', flag_length * 8) # Create a bitvector with the symbol name "flag"

# Since we are using arguments (argv) we can append the program name + the flag
argv = [project.filename] + [flag_chars]

entry_state = project.factory.entry_state(
    args=argv,
    add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}) # these options are not necessary to solve the problem
sim_manager = project.factory.simulation_manager(entry_state) # I can use .simgr as well

good_address = 0x400000 + 0x187d # 0x1876
avoid_address = 0x400000 + 0x1890 # 0x1889
sim_manager.explore(find=good_address, avoid=avoid_address)

if sim_manager.found:
    print("gotten")
    solution = sim_manager.found[0].solver.eval(argv[1], cast_to=bytes)
    print(solution)
else:
    print("not gotten")



