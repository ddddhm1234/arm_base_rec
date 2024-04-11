import ida_kernwin
import idaapi
import ida_idaapi
import idautils
import idc
import itertools

# ============================ Function =====================================
def get_architecture_details():
    inf = idaapi.get_inf_structure()
    if inf.is_64bit():
        addr_size = 8
    elif inf.is_32bit():
        addr_size = 4
    
    
    endianness = "big" if inf.is_be() else "little"

    return (addr_size, endianness)

def detect_by_str():
    addr_size, endian = get_architecture_details()
    refs = []
    for head in idautils.Heads():
        if not idaapi.is_code(idaapi.get_flags(head)):
            continue

        if idc.print_insn_mnem(head).startswith("LDR") and idc.print_operand(head, 1).startswith("="):
            label_val = idc.get_operand_value(head, 1)
            label_val = int.from_bytes(idaapi.get_bytes(label_val, 4), endian)
            if not isinstance(label_val, int):
                continue

            refs.append(label_val)

    refs = set(refs)
    strs = set([x.ea for x in idautils.Strings()])


    occurs = [base for s, r in itertools.product(strs, refs) if (base := r - s) >= 0 and base % 4096 == 0]
    bases = {}
    for o in occurs:
        bases[o] = bases.get(o, 0) + 1

    bases = dict(sorted(bases.items(), key=lambda x: x[1]))
    return bases

def detect_by_func():
    addr_size, endian = get_architecture_details()
    refs = []
    for head in idautils.Heads():
        if not idaapi.is_code(idaapi.get_flags(head)):
            continue

        if idc.print_insn_mnem(head).startswith("LDR") and idc.print_operand(head, 1).startswith("="):
            label_val = idc.get_operand_value(head, 1)
            label_val = int.from_bytes(idaapi.get_bytes(label_val, 4), endian)
            if not isinstance(label_val, int):
                continue

            refs.append(label_val)

    refs = set(refs)
    funcs = set([x for x in idautils.Functions()])

    occurs = [base if base % 4096 == 0 else base - 1 for s, r in itertools.product(funcs, refs) if (base := r - s) and base >= 0 and base % 4096 <= 1]
    bases = {}
    for o in occurs:
        bases[o] = bases.get(o, 0) + 1

    bases = dict(sorted(bases.items(), key=lambda x: x[1]))
    return bases

def find_jumps(si: idaapi.switch_info_t, endian: str, addr_size: int) -> list:
    jtable = []
    e_size = si.get_jtable_element_size()

    # if the jump table is not pointer array
    if not idaapi.is_data(idaapi.get_flags(si.jumps)):
        return jtable

    if e_size != addr_size:
        return jtable

    for num in range(0, si.get_jtable_size()):
        jtable.append(int.from_bytes(idaapi.get_bytes(si.jumps + (num * e_size), e_size), endian) + si.elbase)
    
    return jtable

def detect_by_switch():
    addr_size, endian = get_architecture_details()
    bases = {}
    for head_ea in idautils.Heads():
        if not idaapi.is_code(idaapi.get_flags(head_ea)):
            continue

        # get the information of switch
        si = idaapi.get_switch_info(head_ea)
        if si is None:
            # not switch
            continue

        if not si.has_default():
            # no default case
            continue

        def_target = si.defjump
        jtables = find_jumps(si, endian, addr_size)
        if len(jtables) == 0:
            continue

        base = max(jtables) - def_target
        # the base addr should align to 0x1000
        if not base % 4096 == 0:
            continue

        bases[base] = bases.get(base, 0) + 1
    
    bases = dict(sorted(bases.items(), key=lambda x: x[1]))
    return bases



# ================================= PLUGIN =============================

class BaseShowChooser(ida_kernwin.Choose):
    """
    A simple chooser to be used as an example.
    This chooser will display a list of (Base, HIT) pairs.
    """
    
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [ ["Base", 10], ["HIT", 10] ] # Column headers and widths
        )
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

def generic_handler(callback):
    class Handler(ida_kernwin.action_handler_t):
        def __init__(self):
            ida_kernwin.action_handler_t.__init__(self)

        def activate(self, ctx):
            callback()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS
    return Handler()


class myHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_DISASM:
            for action in myIdaPlugin.actions:
                ida_kernwin.attach_action_to_popup(form, popup, action[0], "ArmBaseFinder/")





def show_bases(bases, title: str="Result"):
    bases = dict(sorted(bases.items(), key=lambda x: x[1], reverse=True))
    items = list([hex(k), str(v)] for k, v in bases.items())
    c = BaseShowChooser(title, items)
    c.Show()

def find_by_str_ref():
    bases = detect_by_str()
    show_bases(bases, "Result of Find By Str Ref")


def find_by_func_ref():
    bases = detect_by_func()
    show_bases(bases, "Result of Find By Func Ref")


def find_by_jmp_table():
    bases = detect_by_switch()
    show_bases(bases, "Result of Find By Jmp Table")


def about():
    ida_kernwin.info("ARMBaseFinder v1.0\nCreated by ru1n")


class myIdaPlugin(ida_idaapi.plugin_t):
    flags = 0  # 插件类别 或者特性
    wanted_name = "ArmBaseFinder"  # 展示名称
    comment = ""  # 插件描述
    help = "A plugin to find arm firmware base addr"  # 帮助信息

    actions = [
        ("ArmBaseFinder:FindByStrRef", "Find By Str Ref", find_by_str_ref),
        ("ArmBaseFinder:FindByFuncRef", "Find By Func Ref", find_by_func_ref),
        ("ArmBaseFinder:FindByJumpTable", "Find By Switch Jump Table", find_by_jmp_table),
        ("ArmBaseFinder:About", "About", about),
    ]

    def init(self):
        for action in self.actions:
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    action[0],
                    action[1],
                    generic_handler(action[2]),
                    None,
                    "",
                    199
                )
            )

        self.hook = myHook()
        self.hook.hook()
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        self.hook.unhook()


            

def PLUGIN_ENTRY():
    return myIdaPlugin()