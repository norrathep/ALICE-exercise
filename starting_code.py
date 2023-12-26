import angr

angr_proj = angr.Project("../bintest/md5-O0",auto_load_libs=False)
cfg = angr_proj.analyses.CFGFast()

# Get a function struct from a specific address
fn_addr = 0x40175c
func = cfg.functions[fn_addr]
print(func)

# To get content of a specific section in binary
section_name = ".text"
sec = angr_proj.loader.main_object.sections_map[section_name]
content = angr_proj.loader.memory.load(sec.vaddr, sec.memsize)
print(content)

# To get a basic block from a given address
bb = angr_proj.factory.block(int(fn_addr))
print(bb)

# Disassemble a specific section
content = angr_proj.loader.memory.load(sec.vaddr, sec.memsize)
disassembly = angr_proj.arch.capstone.disasm(bytearray(content), sec.vaddr)
print(disassembly)
