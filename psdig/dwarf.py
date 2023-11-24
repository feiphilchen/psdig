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
        elif dietype.tag == "DW_TAG_class_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            name = dietype.attributes.get('DW_AT_name').value.decode()
            type_list = [{"type": "class", "size": size, "name":name}]
            return type_list
        elif dietype.tag == "DW_TAG_typedef":
            typedef_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            return self.parse_var_type(cu, typedef_dietype)
        elif dietype.tag == "DW_TAG_const_type":
            const_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            return self.parse_var_type(cu, const_dietype)

    def resolve_args(self, cu, die):
        args = []
        v = []
        for child in die.iter_children():
            if child.tag == 'DW_TAG_formal_parameter':
                arg = {}
                name = child.attributes.get('DW_AT_name')
                if name:
                    arg['name'] = name.value.decode()
                dietype = cu.get_DIE_from_refaddr(cu.cu_offset + child.attributes["DW_AT_type"].value)
                argtype = self.parse_var_type(cu, dietype)
                arg['type'] = argtype
                args.append(arg)
        return args

    def resolve_return(self, cu, die):
        if "DW_AT_type" not in die.attributes:
            return []
        dietype = cu.get_DIE_from_refaddr(cu.cu_offset + die.attributes["DW_AT_type"].value)
        type_list = self.parse_var_type(cu, dietype)
        return type_list

    def __resolve_function(self, cu, die):
        result = {}
        low_pc = die.attributes.get('DW_AT_low_pc')
        if low_pc:
            result['addr'] = low_pc.value
        args = self.resolve_args(cu, die)
        result['args'] = args
        ret = self.resolve_return(cu, die)
        result['ret'] = ret
        return result

    def get_function_name(self, cu, die):
        name = die.attributes.get('DW_AT_name')
        if name:
            parent = die.get_parent()
            return name.value.decode(),parent
        spec = die.attributes.get('DW_AT_specification')
        if spec == None:
            return None,None
        spec_die = cu.get_DIE_from_refaddr(cu.cu_offset + spec.value)
        if spec_die == None:
            return None,None
        die_name = spec_die.attributes.get('DW_AT_name')
        if die_name == None:
            return None,None
        parent = spec_die.get_parent()
        return die_name.value.decode(),parent

    def resolve_function_parent(self, parent):
        class_name = None
        namespace = None
        if parent.tag == 'DW_TAG_class_type':
            class_name = parent.attributes.get('DW_AT_name').value.decode()
            parent = parent.get_parent()
            if parent.tag == 'DW_TAG_namespace':
                namespace = parent.attributes.get('DW_AT_name').value.decode()
        return namespace,class_name

    def fuction_full_name(self, function, class_name, namespace):
        name_list = []
        if namespace:
            name_list.append(namespace)
        if class_name:
            name_list.append(class_name)
        name_list.append(function)
        return "::".join(name_list)

    def parse_function_str(self, func_str):
        name_list = func_str.split("::")
        if len(name_list) == 1:
            return None,None,name_list[0]
        elif len(name_list) == 2:
            return None,name_list[0],name_list[1]
        elif len(name_list) == 3:
            return name_list[0],name_list[1],name_list[2]
        else:
            return None,None,None

    def resolve_function(self, func_str):
        funcs = []
        namespace,class_name,function = self.parse_function_str(func_str)
        if function == None:
            return funcs
        for CU in self.dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_subprogram':
                    funcname,parent = self.get_function_name(CU, child)
                    if funcname == function:
                        result = self.__resolve_function(CU, child)
                        func_ns,func_class = self.resolve_function_parent(parent)
                        if func_ns == namespace and func_class == class_name:
                            result['function'] = self.fuction_full_name(function, class_name, namespace)
                            funcs.append(result)
        return funcs

