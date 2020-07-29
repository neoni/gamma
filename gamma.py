import shutil, re, os, errno

import ida_hexrays
import ida_idaapi
import ida_kernwin as kw
import ida_lines as il
import ida_diskio
import ida_lines
from idaapi import *

__author__ = "neoni"

PLUGIN_NAME = "gamma"

COLOR_VARS = []
COLOR_MEMS = []

# -----------------------------------------------------------------------------
def is_plugin():
    """returns True if this script is executed from within an IDA plugins
    directory, False otherwise."""
    return "__plugins__" in __name__

# -----------------------------------------------------------------------------
def get_dest_filename():
    """returns destination path for plugin installation."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "plugins",
        "%s%s" % (PLUGIN_NAME, ".py"))

# -----------------------------------------------------------------------------
def is_installed():
    """checks whether script is present in designated plugins directory."""
    return os.path.isfile(get_dest_filename())

# -----------------------------------------------------------------------------
def is_ida_version(requested):
    """Checks minimum required IDA version."""
    rv = requested.split(".")
    kv = kw.get_kernel_version().split(".")

    count = min(len(rv), len(kv))
    if not count:
        return False

    for i in range(count):
        if int(kv[i]) < int(rv[i]):
            return False
    return True

# -----------------------------------------------------------------------------
def is_compatible():
    """Checks whether script is compatible with current IDA and
    decompiler versions."""
    min_ida_ver = "7.2"
    return is_ida_version(min_ida_ver) and ida_hexrays.init_hexrays_plugin()

# -----------------------------------------------------------------------------
SELF = __file__
def install_plugin():
    """Installs script to IDA userdir as a plugin."""
    dst = get_dest_filename()
    src = SELF
    if is_installed():
        btnid = kw.ask_yn(kw.ASKBTN_NO,
            "File exists:\n\n%s\n\nReplace?" % dst)
        if btnid is not kw.ASKBTN_YES:
            return False
    else:
        btnid = kw.ask_yn(kw.ASKBTN_NO,
            "This plugin is about to be installed to:\n\n%s\n\nInstall now?" % dst)
        if btnid is not kw.ASKBTN_YES:
            return False

    usrdir = os.path.dirname(dst)
    kw.msg("%s: copying script from \"%s\" to \"%s\" ..." % (PLUGIN_NAME, src, usrdir))
    if not os.path.exists(usrdir):
        try:
            os.makedirs(usrdir)
        except OSError as e:
            if e.errno != errno.EEXIST:
                kw.msg("failed (mkdir)!\n")
                return False
    try:
        shutil.copy(src, dst)
    except:
        kw.msg("failed (copy)!\n")
        return False
    kw.msg(("done\n"
        "Plugin installed - please restart this instance of IDA.\n"))
    return True


# -----------------------------------------------------------------------------
class gamma_hooks_t(ida_hexrays.Hexrays_Hooks):
    """class for handling decompiler events."""

    def _color_var(self, vu, item):
        global COLOR_VARS
        if not item:
            return
        pc = vu.cfunc.get_pseudocode()
        if item in COLOR_VARS:
            for sl in pc:
                sl.line = sl.line.replace(ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR), item)
            COLOR_VARS.remove(item)
        else:
            for sl in pc:
                pos = 0
                while True:
                    pos = sl.line.find(item, pos)
                    if pos < 0:
                        break
                    if not sl.line[pos+len(item)].isalnum():
                        sl.line = sl.line[:pos] + ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR) + sl.line[pos+len(item):]
                        pos += len(ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR))
                    else:
                        pos += 1
                # sl.line = sl.line.replace(item, ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR))
            COLOR_VARS.append(item)
        refresh_idaview_anyway()

    def _contains_item(self, pc, items, remove=False):
        for sl in pc:
            line = self._strip_line(sl.line)
            s = ''.join(items)
            count = line.count(s)
            if count <= 0:
                continue
            #print(count, line)
            start = 0
            fact = 0
            for i in range(13):  # max 13 times to try to match
                if fact == count:
                    continue # find all arguments
                pos = len(sl.line)
                found = True
                pos = sl.line.find(items[-1], start, pos)
                old_start = start
                start = pos + 1
                if pos < 0 or (pos+len(items[-1])<len(sl.line) and sl.line[pos+len(items[-1])].isalnum()) or \
                    ((pos-1) >= 0 and sl.line[pos-1].isalnum()):
                    continue
                for item in items[-2::-1]:
                    pos = sl.line.rfind(item, old_start, pos)
                    if pos < 0 or (pos+len(item)<len(sl.line) and sl.line[pos+len(item)].isalnum()) or \
                        ((pos-1) >= 0 and sl.line[pos-1].isalnum()):
                        found = False
                        break
                if found:
                    fact += 1
                    for item in items:
                        pos = sl.line.find(item, pos, start)
                        if pos+len(item)==len(sl.line) or not sl.line[pos+len(item)].isalnum() or pos - 1 < 0 or not sl.line[pos-1].isalnum():
                            if remove:
                                sl.line = sl.line[:pos-2] + item + sl.line[pos+len(item)+2:]
                                start -= 4
                            else:
                                sl.line = sl.line[:pos] + ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR) + sl.line[pos+len(item):]
                                pos += len(ida_lines.COLSTR(item, ida_lines.SCOLOR_ERROR))
                                start += 4
                        elif pos < 0:
                            continue
                        else:
                            pos += 1


    def _color_mem(self, vu, items):
        global COLOR_MEMS
        if not items:
            return
        if len(items) == 1:
            self._color_var(vu, items[0])
            return
        pc = vu.cfunc.get_pseudocode()
        if items in COLOR_MEMS:
            self._contains_item(pc, items, True)
            COLOR_MEMS.remove(items)
        else:
            self._contains_item(pc, items, False)
            COLOR_MEMS.append(items)

        refresh_idaview_anyway()

    def _strip_line(self, sline):
        line = re.sub(r'\(0000............', '', sline)
        line = ''.join([c for c in line if ord(c) >= 0x20])
        line = line.replace('[ ', '[').replace(' ]', ']')
        line = re.sub(r'(?<=[^ ])([ ]{2})(?=[^ ]|$)', ' ', line) # replace two space
        return line

    def right_click(self, vu):
        if vu.get_current_item(USE_MOUSE):
            item = None
            cit = vu.item.citype
            if cit == VDI_LVAR:
                item = vu.item.l.name
                self._color_var(vu, item)
            elif cit == VDI_EXPR:
                if vu.item.e.v:
                    lvars = vu.cfunc.get_lvars()
                    var = lvars[vu.item.e.v.idx]
                    if var:
                        item = var.name
                        self._color_var(vu, item)
                else:
                    sl = vu.cfunc.get_pseudocode()[vu.cpos.lnnum]
                    line = self._strip_line(sl.line)
                    items = []
                    x = vu.cpos.x # maybe inaccuracy
                    while x < len(line) and ((not line[x].isalnum()) and (line[x] not in ['[', '_', ' '])):
                        x += 1
                    if x >= len(line):
                        return 0
                    #print(sl.line)
                    #print(x)
                    #print(line)
                    tmp = line[x]
                    for i in range(x-1, -1, -1):
                        if not line[i].isalnum() and line[i] is not '_':
                            break
                        tmp = line[i] + tmp
                    for i in range(x+1, len(line)):
                        if line[i] is ' ':
                            if tmp:
                                items.append(tmp)
                                tmp = ''
                        elif line[i] is '[':
                            if tmp:
                                items.append(tmp)
                                tmp = ''
                            items.append(line[i])
                        elif line[i] is ']':
                            if tmp:
                                items.append(tmp)
                            if '[' in items:
                                items.append(line[i])
                            break
                        elif line[i] is '-':
                            if tmp:
                                items.append(tmp)
                            if line[i+1] is '>':
                                tmp = '-'
                            else:
                                break
                        elif line[i] is '>':
                            if tmp is '-':
                                tmp = ''
                                items.append('->')
                            else:
                                break
                        elif line[i].isalnum() or line[i] is '_':
                            tmp = tmp + line[i]
                        else:
                            if tmp:
                                items.append(tmp)
                            break
                    #print(items)
                    self._color_mem(vu, items)
        return 0


class gamma_plugin_t(ida_idaapi.plugin_t):
    """plugin class."""
    flags = ida_idaapi.PLUGIN_HIDE
    comment = PLUGIN_NAME
    help = PLUGIN_NAME
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.gamma_hooks = None
        if not is_compatible():
            kw.msg("%s: decompiler not available, skipping." % PLUGIN_NAME)
            return ida_idaapi.PLUGIN_SKIP

        self.gamma_hooks = gamma_hooks_t()
        self.gamma_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        return

    def term(self):
        if self.gamma_hooks:
            self.gamma_hooks.unhook()
        return

# -----------------------------------------------------------------------------
def PLUGIN_ENTRY():
    """plugin entry point."""
    return gamma_plugin_t()

# -----------------------------------------------------------------------------
def SCRIPT_ENTRY():
    """script entry point."""
    if not is_plugin():
        (kw.info("Success!") if install_plugin() else
            kw.warning("Error! Plugin could not be installed!"))
    return

# -----------------------------------------------------------------------------
HL_FLAGS = kw.HIF_LOCKED | kw.HIF_NOCASE if is_ida_version("7.4") else kw.HIF_LOCKED
SCRIPT_ENTRY()
