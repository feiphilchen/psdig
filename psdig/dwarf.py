# SPDX-License-Identifier: GPL-3.0-or-later
# Author: feiphilchen@gmail.com

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

    def dwarf_open(self, filename, is_link=False):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            if not is_link:
                self.text_start = self.get_text_start(elffile)
            debug_link = self.debug_link(elffile)
            if debug_link:
                self.dwarf_open(debug_link, is_link=True)
                return
            if not elffile.has_dwarf_info():
                return None
            self.dwarfinfo = elffile.get_dwarf_info()

    def get_text_start(self, elffile):
        sect = elffile.get_section_by_name('.text')
        return sect['sh_addr'] - sect['sh_offset'] 

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
            obj = {"type": "enum", "size": size}
            if 'DW_AT_name' in dietype.attributes:
                obj['name'] = dietype.attributes.get('DW_AT_name').value.decode()
            type_list = [obj]
            return type_list
        elif dietype.tag == "DW_TAG_structure_type":
            obj = {"type": "struct"}
            if 'DW_AT_byte_size' in  dietype.attributes:
                obj['size'] = dietype.attributes.get('DW_AT_byte_size').value
            if 'DW_AT_name' in dietype.attributes:
                obj['name'] = dietype.attributes.get('DW_AT_name').value.decode()
            return [obj]
        elif dietype.tag == "DW_TAG_union_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            if dietype.attributes.get('DW_AT_name'):
                name = dietype.attributes.get('DW_AT_name').value.decode()
                type_list = [{"type": "union", "size": size, "name":name}]
            else:
                type_list = [{"type": "union", "size": size}]
            return type_list
        elif dietype.tag == "DW_TAG_class_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            if dietype.attributes.get('DW_AT_name'):
                name = dietype.attributes.get('DW_AT_name').value.decode()
                type_list = [{"type": "class", "size": size, "name":name}]
            else:
                type_list = [{"type": "class", "size": size}]
            return type_list
        elif dietype.tag == "DW_TAG_typedef":
            typedef_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            return self.parse_var_type(cu, typedef_dietype)
        elif dietype.tag == "DW_TAG_const_type":
            if "DW_AT_type" in dietype.attributes:
                const_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
                return self.parse_var_type(cu, const_dietype)
            else:
                return [{"type": "const", "size": 1}]
        elif dietype.tag == "DW_TAG_subroutine_type":
            if "DW_AT_type" in dietype.attributes:
                subrouting_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
                return self.parse_var_type(cu, subrouting_dietype)
            else:
                return [{"type": "subrouting", "size": 1}]
        elif dietype.tag == "DW_TAG_array_type":
            array_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            return self.parse_var_type(cu, array_dietype)
        elif dietype.tag == "DW_TAG_volatile_type":
            vol_dietype = cu.get_DIE_from_refaddr(cu.cu_offset + dietype.attributes["DW_AT_type"].value)
            return self.parse_var_type(cu, vol_dietype)

    def resolve_args(self, cu, die):
        args = []
        v = []
        for child in die.iter_children():
            if child.tag == 'DW_TAG_formal_parameter':
                arg = {}
                name = child.attributes.get('DW_AT_name')
                if name:
                    arg['name'] = name.value.decode()
                if "DW_AT_type" not in child.attributes:
                    continue
                dietype = cu.get_DIE_from_refaddr(cu.cu_offset + child.attributes["DW_AT_type"].value)
                argtype = self.parse_var_type(cu, dietype)
                arg['type'] = argtype
                args.append(arg)
        return args

    def resolve_return(self, cu, die):
        if "DW_AT_type" not in die.attributes:
            return []
        cu  = die.cu
        offset = cu.cu_offset + die.attributes["DW_AT_type"].value
        dietype = cu.get_DIE_from_refaddr(offset)
        type_list = self.parse_var_type(cu, dietype)
        return type_list

    def resolve_abstract_origin_addr(self, cu, die):
        if die.attributes.get('DW_AT_sibling') != None:
            next_sibling = cu.get_DIE_from_refaddr(cu.cu_offset + die.attributes.get('DW_AT_sibling').value)
            if next_sibling.attributes.get('DW_AT_abstract_origin') != None:
                origin_value = next_sibling.attributes.get('DW_AT_abstract_origin').value
                if origin_value == die.offset:
                    low_pc = next_sibling.attributes.get('DW_AT_low_pc')
                    if low_pc != None:
                        return low_pc.value - self.text_start
        return None

    def __resolve_function(self, cu, die, resolve_args=True):
        result = {}
        low_pc = die.attributes.get('DW_AT_low_pc')
        if low_pc:
            result['addr'] = low_pc.value - self.text_start
        else:
            addr = self.resolve_abstract_origin_addr(cu, die)
            if addr != None:
                result['addr'] = addr
        if resolve_args:
            origin = die.attributes.get('DW_AT_abstract_origin')
            if origin != None:
                origin_node = self.dwarfinfo.get_DIE_from_refaddr(origin.value)
                args = self.resolve_args(origin_node.cu, origin_node)
            else:
                args = self.resolve_args(cu, die)
            result['args'] = args
        return result

    def get_function_name(self, cu, die):
        name = die.attributes.get('DW_AT_name')
        if name:
            parent = die.get_parent()
            return name.value.decode(),parent,die
        origin = die.attributes.get('DW_AT_abstract_origin')
        if origin != None:
            try:
                origin_node = self.dwarfinfo.get_DIE_from_refaddr(origin.value)
                if origin_node == None:
                    return None,None,None
            except:
                return None,None,None
            name = origin_node.attributes.get('DW_AT_name')
            if name == None:
                return None,None,None
            try:
                parent = origin_node.get_parent()
            except:
                return None,None,None
            return name.value.decode(),parent,origin_node
        spec = die.attributes.get('DW_AT_specification')
        if spec == None:
            return None,None,None
        spec_die = cu.get_DIE_from_refaddr(cu.cu_offset + spec.value)
        if spec_die == None:
            return None,None,None
        die_name = spec_die.attributes.get('DW_AT_name')
        if die_name == None:
            return None,None,None
        parent = spec_die.get_parent()
        return die_name.value.decode(),parent,spec_die

    def resolve_function_parent(self, parent):
        class_name = None
        namespace = None
        if parent == None:
            return namespace,class_name
        if parent.tag == 'DW_TAG_namespace':
            namespace = parent.attributes.get('DW_AT_name').value.decode()
            return namespace,class_name
        if parent.tag == 'DW_TAG_class_type' or parent.tag == 'DW_TAG_structure_type':
            class_name = parent.attributes.get('DW_AT_name').value.decode()
            parent = parent.get_parent()
            if parent.tag == 'DW_TAG_namespace':
                namespace = parent.attributes.get('DW_AT_name').value.decode()
        return namespace,class_name

    def args_to_dec(self, args):
        arg_decls = []
        for arg in args:
            decl = []
            if 'type' not in arg or arg['type'] == None:
                break
            for t in arg['type']:
                if t['type'] == 'ptr':
                    decl.insert(0, '*')
                elif t['type'] == 'struct' or t['type'] == 'class' or \
                    t['type'] == 'union' or t['type'] == 'enum':
                    if 'name' in t:
                        decl.insert(0, '%s %s' % (t['type'], t['name']))
                    else:
                        decl.insert(0, '%s' % (t['type']))
                elif 'name' in t:
                    decl.insert(0, t['name'])
                else:
                    decl.insert(0, 'void')
            decl_str = ' '.join(decl)
            arg_decls.append(decl_str)
        return ','.join(arg_decls)

    def function_full_name(self, function, class_name, namespace):
        name_list = []
        if namespace:
            name_list.append(namespace)
        if class_name:
            name_list.append(class_name)
        name_list.append(function)
        full_name = "::".join(name_list)
        return full_name

    def parse_function_str(self, func_str):
        hit = re.match('([^(]+)\((.*)\)', func_str)
        if hit:
            func_str = hit.group(1)
            args_decl = hit.group(2)
        else:
            args_decl = None
        name_list = func_str.split("::")
        if len(name_list) == 1:
            return None,None,name_list[0],args_decl
        elif len(name_list) == 2:
            return None,name_list[0],name_list[1],args_decl
        elif len(name_list) == 3:
            return name_list[0],name_list[1],name_list[2],args_decl
        else:
            return None,None,None,args_decl

    def func_args_eq(self, decl_0, decl_1):
        decl_0 = decl_0.replace(' ', '')
        decl_1 = decl_1.replace(' ', '')
        return decl_0 == decl_1

    def resolve_function(self, func_str):
        funcs = []
        namespace,class_name,function,func_args = self.parse_function_str(func_str)
        if function == None:
            return funcs
        for CU in self.dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_subprogram':
                    funcname,parent,decl = self.get_function_name(CU, child)
                    if funcname == function:
                        result = self.__resolve_function(CU, child)
                        if result == None or 'addr' not in result:
                            continue
                        args_decl = self.args_to_dec(result['args'])
                        func_ns,func_class = self.resolve_function_parent(parent)
                        if func_args != None and not self.func_args_eq(func_args, args_decl):
                            continue
                        if func_ns == namespace and func_class == class_name:
                            result['function'] = self.function_full_name(function, class_name, namespace)
                            result['ret'] =  self.resolve_return(CU, decl)
                            funcs.append(result)
        return funcs

    def all_functions(self):
        functions = []
        for CU in self.dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_subprogram':
                    funcname,parent,decl = self.get_function_name(CU, child)
                    if funcname == None:
                        continue
                    result = self.__resolve_function(CU, child)
                    if result == None or 'addr' not in result:
                        continue
                    args_decl = self.args_to_dec(result['args'])
                    func_ns,func_class = self.resolve_function_parent(parent)
                    fullname = self.function_full_name(funcname,func_class,func_ns)
                    if func_class != None:
                        decl = fullname + '(' + args_decl + ')'
                        functions.append(decl)
                    else:
                        functions.append(fullname)
        return sorted(list(set(functions)))

