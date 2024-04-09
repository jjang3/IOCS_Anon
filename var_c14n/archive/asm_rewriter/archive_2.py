 if store_or_load == "store":
                        new_inst_type = "mov_store_gs" # Need to think about how to make this work for NGINX
                        if vuln == True:
                            if param == True:
                                # This needs to be "#" with the register to prevent exploit 
                                # line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (verifier_metadata, new_inst_type, 
                                #                                                      temp_inst.src, tgt_offset, value), dis_inst)
                                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s\t%s, %d, %d" % 
                                              (dis_inst, verifier_metadata, new_inst_type, 
                                               temp_inst.src, tgt_offset, value), dis_inst)
                            else:
                                # line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s, %d, %d" % (verifier_metadata, new_inst_type, 
                                #                                                         temp_inst.src, tgt_offset, value), dis_inst)
                                line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t%s\t%s, %d, %d" % 
                                              (dis_inst, verifier_metadata, new_inst_type, 
                                               temp_inst.src, tgt_offset, value), dis_inst)
                        else:
                            line = re.sub(r"(\b[a-z]+\b).*", "%s\t%s\t#%s\t%s, %d, %d" % 
                                          (dis_inst, verifier_metadata, new_inst_type, 
                                           temp_inst.src, tgt_offset, value), dis_inst)
                        patch_inst_line = "\t%s\t%s, %d, %d" % (new_inst_type, temp_inst.src, tgt_offset, value)
                        
# line = re.sub(r"(\b[a-z]+\b).*", "#%s\t%s\t%s, %d" % 
            #             (dis_inst, new_inst_type, temp_inst.dest, tgt_offset), dis_inst)
    # logger.debug(bn_var)
    vuln = False
    param = False
    # if bn_var.arg == True and bn_var.patch_inst.inst_type != "lea":
    #     return dis_inst
    # elif bn_var.arg == True and bn_var.patch_inst.inst_type == "lea":
    #     logger.debug("Here")
    #     new_inst_type = "lea_store_gs" 
    #     line = ""
    #     for var in dwarf_var_info:
    #         if var.offset_expr == bn_var.offset_expr:
    #             # Found that base struct object is being passed as an argument, need to lea_store_gs all the members as well
    #             logger.error("Found struct object")
    #             if var.struct != None:
    #                 for member in var.struct.member_list:
    #                     # logger.debug(offset_targets)
    #                     offset_value = 0
    #                     for offset in offset_targets:
    #                         if offset[0] == member.offset_expr:
    #                             offset_value = offset[1]
    #                     if offset_value != None and member.offset_expr != None:
    #                         line = "\t%s\t%s, %d\n" % (new_inst_type, member.offset_expr, offset_value)
    #                         patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, member.offset_expr, offset_value)
                        
    #                     if line != "" and line not in lea_list:
    #                         lea_list.append(line)
    #                         patch_inst_list.append(patch_inst_line)
    #     if line == "" and bn_var.offset_expr != None:
    #         line = "\t%s\t%s, %d\n" % (new_inst_type, bn_var.offset_expr, tgt_offset)
    #         patch_inst_line = "\t%s\t%s, %d" % (new_inst_type, bn_var.offset_expr, tgt_offset)
    #         if line != "" and line not in lea_list:
    #             lea_list.append(line)
    #             patch_inst_list.append(patch_inst_line)
    #     logger.debug(bn_var)
    #     logger.debug(lea_list)
    #     return dis_inst
    # elif bn_var.arg == False:
    #     for var in dwarf_var_info:
    #         if var.offset_expr == bn_var.offset_expr:
    #             logger.warning("Found the variable in DWARF table")
    #             if var.vuln == True:
    #                 logger.warning("Found vulnerable variable")
    #                 vuln = True
    #         if var.tag == "DW_TAG_formal_parameter":
    #             logger.warning("Parameter found")
    #             if check_arg_reg(temp_inst.src):
    #                 logger.error("Parameter setup")
    #                 param = True
    #             else:
    #                 logger.error("False")
                
                # logger.debug(arg_reg.pop())
                
                
                

# new_node_candidates = list()
        # remove_node_candidates = list()
        # # pprint.pprint(target_fun_var_info)
        # for fun in target_fun_var_info:
        #     for var in target_fun_var_info[fun]:
        #         var: VarData
        #         target_node: taint_analysis.PtrOffsetTreeNode
        #         target_node = None
        #         for tree in ptr_offset_trees:
        #             tree: taint_analysis.PtrOffsetTree
        #             # tree.print_tree()    
        #             target_node = tree.find_node_by_fun_name_and_offset(var.fun_name, var.offset)
        #             if target_node:
        #                 parent_node: taint_analysis.PtrOffsetTreeNode
        #                 parent_node = tree.find_parent(target_node, find_root=True)
        #                 for search_var in dwarf_fun_var_info[parent_node.fun_name]:
        #                     if search_var.offset == parent_node.local_offset:
        #                         log.critical("Found the proper patching target")
        #                         print(search_var)
        #                         new_node_candidates.append(parent_node)
        #                 target_node.print_node()
        #                 remove_node_candidates.append(target_node)
        #                 break
        
        # pprint.pprint(target_fun_var_info) 
        # for cand in remove_node_candidates:
        #     cand: taint_analysis.PtrOffsetTreeNode
        #     cand.print_node()
        #     for fun in target_fun_var_info:
        #         for i in range(len(target_fun_var_info[fun]) - 1, -1, -1):  # Iterate backwards
        #             var = target_fun_var_info[fun][i]
        #             if cand.local_offset == var.offset and cand.fun_name == var.fun_name:  # Replace <your_condition_here> with your specific condition 
        #                 log.error("Deleting")
        #                 cand.print_node()
        #                 del target_fun_var_info[fun][i]
        
        # for cand in new_node_candidates:
        #     cand: taint_analysis.PtrOffsetTreeNode
        #     for fun in all_dwarf_info:
        #         if fun == cand.fun_name:
        #             for var in all_dwarf_info[fun]:
        #                 var: VarData
        #                 if var.offset == cand.local_offset:
        #                     # log.critical("Add")
        #                     # print(var)
        #                     cand.print_node()
        #                     try:
        #                         if var not in target_fun_var_info[fun]:
        #                             target_fun_var_info[fun].append(var)
        #                     except:
        #                         log.debug("Create a new list")
        #                         target_fun_var_info[fun] = list()
        #                         target_fun_var_info[fun].append(var)