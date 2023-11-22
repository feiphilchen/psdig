import os
import sys
import re
import json
import logging
import traceback
import pkgutil
import threading
import binascii
from elftools.elf.elffile import ELFFile
from .conf import LOGGER_NAME

class Dwarf(object):
    def __init__(self, filename):
        self.dwarf_open(filename)

    def dwarf_open(self, filename):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            debug_link = self.debug_link(elffile)
            if debug_link:
                self.dwarf_open(debug_link)
                return
            if not elffile.has_dwarf_info():
                return None
            self.dwarfinfo = elffile.get_dwarf_info()

    def debug_link(self, elffile):
        debug_link = None
        build_id = None
        for section in elffile.iter_sections():
            if section.name == ".gnu_debuglink":
                data = section.data()
                fdata = data[0:data.find(b"\x00")]
                debug_link = fdata
            elif section.name == ".note.gnu.build-id":
                data = section.data()
                hash = data[16:]
                value = binascii.hexlify(hash).decode("ascii")
                build_id = value
        debug_prefixes = ["/usr/lib/debug/.build-id/"]
        if build_id and debug_link:
            for prefix in debug_prefixes:
                path = os.path.join(prefix, build_id[0:2], build_id[2:] + ".debug")
                if os.path.isfile(path):
                    return path
        return None

    def resolve_function(self, funcname):
        result = None
        for CU in self.dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            #print(CU.cu_die_offset)
            #print('    Top DIE with tag=%s' % top_DIE.tag)
            result = self.die_walk(CU, top_DIE, funcname)
            if result != None:
                return result
        return result

    def die_walk(self, cu, die, funcname):
        if die.tag == 'DW_TAG_subprogram':
            die_name = die.attributes.get('DW_AT_name')
            if die_name and die_name.value.decode() == funcname:
                addr = die.attributes.get('DW_AT_low_pc').value
                args = self.resolve_args(cu, die)
                ret = self.resolve_return(cu, die)
                return {"function":funcname, "addr":addr, "args":args, "ret": ret}
        for child in die.iter_children():
            result = self.die_walk(cu, child, funcname)
            if result != None:
                return result
        return None

    def resolve_ptr_addr(self, cu, ptr_dietype, mb):
        dietype = cu.get_DIE_from_refaddr(cu.cu_offset + ptr_dietype.attributes["DW_AT_type"].value)
        if dietype.has_children:
            for child in dietype.iter_children():
                name = child.attributes.get('DW_AT_name').value.decode()
                if name == mb:
                    offset = child.attributes.get('DW_AT_data_member_location').value
                    mb_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + child.attributes["DW_AT_type"].value)
                    inst = {"inst": "ptr_addr", "args":[offset]}
                    return inst,mb_dietype
        return None,None

    def resolve_addr(self, cu, dietype, mb):
        if dietype.has_children:
            for child in dietype.iter_children():
                name = child.attributes.get('DW_AT_name').value.decode()
                if name == mb:
                    offset = child.attributes.get('DW_AT_data_member_location').value
                    mb_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + child.attributes["DW_AT_type"].value)
                    inst = {"inst": "addr", "args":[offset]}
                    return inst,mb_dietype
        return None,None

    def is_string(self, cu, dietype):
        if dietype.tag == "DW_TAG_pointer_type":
            next_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            if next_dietype.attributes.get('DW_AT_name').value.decode() == 'char':
                return True
        return False

    def resolve_vars(self, cu, arg_dies, variables):
        var_insts = {}
        for var_def in variables:
            name = var_def.split("=")[0]
            statement = var_def.split("=")[1]
            params = re.split(r"(->|\.)", statement)
            v = params.pop(0)
            instructions = []
            dietype = cu.get_DIE_from_refaddr(cu.cu_offset + arg_dies[v].attributes["DW_AT_type"].value)
            inst = {"inst":"base", "args":[v]}
            instructions.append(inst)
            while len(params) > 0:
                if params[0] == '->':
                    inst,dietype = self.resolve_ptr_addr(cu, dietype, params[1])
                    if inst:
                        instructions.append(inst)
                    params.pop(0)
                    params.pop(0)
                elif params[0] == '.':
                    inst,dietype = self.resolve_addr(cu, dietype, params[1])
                    if inst:
                        instructions.append(inst)
                    params.pop(0)
                    params.pop(0)
            if self.is_string(cu, dietype):
                inst = {"inst":"read_str", "args":[]}
            else:
                size = dietype.attributes.get('DW_AT_byte_size').value
                inst = {"inst":"read_bytes", "args":[size]}
            instructions.append(inst)
            var_insts[name] = instructions
        return var_insts

    def parse_var_type(self, cu, dietype):
        if dietype.tag == "DW_TAG_pointer_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            type_list = [{"type": "ptr", "size": size}]
            if 'DW_AT_type' in dietype.attributes:
                parent_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
                parent_type_list = self.parse_var_type(cu, parent_dietype)
                return type_list + parent_type_list
            else:
                return type_list
        elif dietype.tag == "DW_TAG_base_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            name = dietype.attributes.get('DW_AT_name').value.decode()
            type_list = [{"type": "base", "size": size, "name":name}]
            return type_list
        elif dietype.tag == "DW_TAG_enumeration_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            type_list = [{"type": "enum", "size": size}]
            return type_list
        elif dietype.tag == "DW_TAG_structure_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            name = dietype.attributes.get('DW_AT_name').value.decode()
            type_list = [{"type": "struct", "size": size, "name":name}]
            return type_list
        elif dietype.tag == "DW_TAG_union_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            name = dietype.attributes.get('DW_AT_name').value.decode()
            type_list = [{"type": "union", "size": size, "name":name}]
            return type_list
        elif dietype.tag == "DW_TAG_typedef":
            typedef_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            return self.parse_var_type(cu, typedef_dietype)

    def resolve_args(self, cu, die):
        args = []
        v = []
        for child in die.iter_children():
            if child.tag == 'DW_TAG_formal_parameter':
                arg = {}
                name = child.attributes.get('DW_AT_name').value.decode()
                dietype = cu.get_DIE_from_refaddr(cu.cu_offset + child.attributes["DW_AT_type"].value)
                argtype = self.parse_var_type(cu, dietype)
                arg['name'] = name
                arg['type'] = argtype
                args.append(arg)
        return args

    def resolve_return(self, cu, die):
        if "DW_AT_type" not in die.attributes:
            return []
        dietype = cu.get_DIE_from_refaddr(cu.cu_offset + die.attributes["DW_AT_type"].value)
        type_list = self.parse_var_type(cu, dietype)
        return type_list


