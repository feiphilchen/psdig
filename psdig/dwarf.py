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
import time
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class
from .conf import LOGGER_NAME

class Dwarf(object):
    def __init__(self, filename):
        self.text_syms = None
        self.addr_cache = {}
        self.dwarf_open(filename)

    def dwarf_open(self, filename):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            self.text_start = self.get_text_start(elffile)
            debug_link = self.debug_link(elffile)
            if debug_link:
                self.dwarf_open_debuglink(debug_link)
                return
            if not elffile.has_dwarf_info():
                return None
            self.dwarfinfo = elffile.get_dwarf_info()
            self.sym_file = filename

    def dwarf_open_debuglink(self, filename):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            if not elffile.has_dwarf_info():
                return None
            self.dwarfinfo = elffile.get_dwarf_info()
            self.sym_file = filename

    def parse_text_symbols(self, sym_file):
        self.text_syms = {}
        lines = os.popen(f'nm -C {sym_file}').readlines()
        for line in lines:
            hit = re.match('([0-9a-zA-Z]+)\\s+[TW]\\s+(.*)$', line)
            if hit:
                func_addr = int(hit.group(1), 16)
                func_name = hit.group(2)
                self.text_syms[func_name] = func_addr

    def addr2line(self, addr):
        cmd = "addr2line -e %s 0x%x" % (self.sym_file, addr)
        result = os.popen(cmd).read().strip()
        result = result.split(':')
        if len(result) != 2 or not result[1].isdigit():
            return None,None
        if result[0] == '??':
            return None,None
        else:
            return result[0],int(result[1])

    def addr2func(self, addr):
        if addr in self.addr_cache:
            return self.addr_cache[addr]
        cmd = "addr2line -f -e %s 0x%x" % (self.sym_file, addr)
        result = os.popen(cmd).read().splitlines()
        func = result[0]
        file_lineno = result[1]
        if func == '??':
            self.addr_cache[addr] = None,None,None
            return None,None,None
        result = file_lineno.split(':')
        if len(result) != 2:
            self.addr_cache[addr] = None,None,None
            return None,None,None
        if result[0] == '??':
            self.addr_cache[addr] = None,None,None
            return None,None,None
        else:
            lineno = result[1].split()[0]
            self.addr_cache[addr] = func,result[0],int(lineno)
            return func,result[0],int(lineno)

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

    def get_die_by_refaddr(self, cu, attr):
        if attr.form in ['DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_udata']:
            return cu.get_DIE_from_refaddr(cu.cu_offset + attr.value)
        else:
            return cu.dwarfinfo.get_DIE_from_refaddr(attr.value)

    def parse_var_type(self, cu, dietype):
        if dietype.tag == "DW_TAG_pointer_type":
            size = dietype.attributes.get('DW_AT_byte_size').value
            type_list = [{"type": "ptr", "size": size}]
            if 'DW_AT_type' in dietype.attributes:
                parent_dietype = self.get_die_by_refaddr(cu, dietype.attributes["DW_AT_type"])
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
            typedef_dietype = self.get_die_by_refaddr(cu, dietype.attributes["DW_AT_type"])
            return self.parse_var_type(cu, typedef_dietype)
        elif dietype.tag == "DW_TAG_const_type":
            if "DW_AT_type" in dietype.attributes:
                const_dietype = self.get_die_by_refaddr(cu, dietype.attributes["DW_AT_type"])
                return self.parse_var_type(cu, const_dietype)
            else:
                return [{"type": "const", "size": 1}]
        elif dietype.tag == "DW_TAG_subroutine_type":
            if "DW_AT_type" in dietype.attributes:
                subrouting_dietype = self.get_die_by_refaddr(cu, dietype.attributes["DW_AT_type"])
                return self.parse_var_type(cu, subrouting_dietype)
            else:
                return [{"type": "subrouting", "size": 1}]
        elif dietype.tag == "DW_TAG_array_type":
            array_dietype = self.get_die_by_refaddr(cu, dietype.attributes["DW_AT_type"])
            return self.parse_var_type(cu, array_dietype)
        elif dietype.tag == "DW_TAG_volatile_type":
            vol_dietype = self.get_die_by_refaddr(cu, dietype.attributes["DW_AT_type"])
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
                dietype = self.get_die_by_refaddr(cu, child.attributes["DW_AT_type"])
                argtype = self.parse_var_type(cu, dietype)
                arg['type'] = argtype
                args.append(arg)
        return args

    def resolve_return(self, cu, die):
        if "DW_AT_type" not in die.attributes:
            return []
        cu  = die.cu
        offset = cu.cu_offset + die.attributes["DW_AT_type"].value
        dietype = self.get_die_by_refaddr(cu, die.attributes["DW_AT_type"])
        type_list = self.parse_var_type(cu, dietype)
        return type_list

    def resolve_abstract_origin_addr(self, cu, die):
        if die.attributes.get('DW_AT_sibling') != None:
            next_sibling = self.get_die_by_refaddr(cu, die.attributes.get('DW_AT_sibling'))
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
                origin_node = self.get_origin(cu, origin)
                args = self.resolve_args(origin_node.cu, origin_node)
            else:
                args = self.resolve_args(cu, die)
            result['args'] = args
        return result

    def get_origin(self, cu, origin):
        return self.get_die_by_refaddr(cu, origin)

    def get_function_name(self, cu, die):
        origin = die.attributes.get('DW_AT_abstract_origin')
        if origin != None:
            origin_node = self.get_origin(cu, origin)
            if origin_node == None:
                return None,None,None
            die = origin_node
        name = die.attributes.get('DW_AT_name')
        if name:
            parent = die.get_parent()
            return name.value.decode(),parent,die
        spec = die.attributes.get('DW_AT_specification')
        if spec == None:
            return None,None,None
        spec_die = self.get_die_by_refaddr(cu, spec)
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
        if self.text_syms == None:
            self.parse_text_symbols(self.sym_file)
        funcs = []
        if func_str not in self.text_syms:
            return funcs
        func_addr = self.text_syms[func_str]
        file,lineno = self.addr2line(func_addr)
        for CU in self.dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            if top_DIE.tag != 'DW_TAG_compile_unit':
                continue
            low_pc = top_DIE.attributes.get('DW_AT_low_pc')
            high_pc = top_DIE.attributes.get('DW_AT_high_pc')
            addr_in_range = False
            if low_pc != None and high_pc != None:
                low_addr = low_pc.value
                highpc_attr_class = describe_form_class(high_pc.form)
                if highpc_attr_class == 'address':
                    high_addr = high_pc.value
                elif highpc_attr_class == 'constant':
                    high_addr = low_addr + high_pc.value
                else:
                    continue
                if func_addr < low_addr or func_addr >= high_addr:
                    continue
                addr_in_range = True
            if not addr_in_range:
                if top_DIE.get_full_path() != file:
                    continue
            for child in top_DIE.iter_children():
                if child.tag == 'DW_TAG_subprogram':
                    low_pc = child.attributes.get('DW_AT_low_pc')
                    if low_pc:
                        low_pc_value = low_pc.value
                    else:
                        low_pc_value = None
                    if low_pc_value == func_addr:
                        funcname,parent,decl = self.get_function_name(CU, child)
                        result = self.__resolve_function(CU, child)
                        if result == None:
                            continue
                        result['addr'] = func_addr - self.text_start
                        args_decl = self.args_to_dec(result['args'])
                        full_name = func_str.split('(')[0]
                        result['function'] = full_name
                        result['ret'] =  self.resolve_return(CU, decl)
                        funcs.append(result)
                        return funcs
        return funcs

    def all_functions(self):
        if self.text_syms == None:
            self.parse_text_symbols(self.sym_file)
        functions = []
        for func in self.text_syms:
            functions.append(func)
        return sorted(list(set(functions)))

