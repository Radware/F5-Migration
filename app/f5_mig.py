#!/usr/bin/python

import re
import os
import tarfile
import ipaddress
import copy
import sys
import json
# import datetime

try:
    from app import app
except Exception as e:
    pass
from app.global_variables import *


def fun_f5_mig(filename, project_name, mode):
    global route_list
    global compres_id
    global if_id
    global hc_id
    global gw_id
    global lacp_id
    global trunk_id
    global filt_id
    global taggedPorts
    global loglines
    global tmp_list
    global logbanner1
    global logbanner2
    global prefixToMaskDict
    global advhcSupTypes
    global metricDict
    global defProfDict
    global defPersistDict
    global dport_dict
    global timezone_dict
    global log1banner
    global log2banner
    global log1str
    global log2str

    #####################
    #                    #
    #    Function def     #
    #                    #
    #####################

    def fun_create_empty_dicts():
        global filter_dict
        global compres_dict
        global persist_dict
        global gw_dict
        global profDict
        global virt_dict
        global trunk_dict
        global lacp_dict
        global poolDict
        global nodeDict
        global monitorDict
        global ifDict
        global floatVlanDict
        global floatIfDict
        global vlanDict
        global tmpDict
        global long_names_dict
        global mng_dict
        global ha_dict
        global sync_list
        global to_filter_list
        global snatt_dict
        global snatp_dict
        global rport_dict
        global cntclss_dict
        global cntrule_dict
        global dataclss_dict
        dataclss_dict = {}
        rport_dict = {}
        cntclss_dict = {}
        cntrule_dict = {}
        snatt_dict = {}
        snatp_dict = {}
        filter_dict = {}
        compres_dict = {}
        persist_dict = {}
        gw_dict = {}
        profDict = {}
        virt_dict = {}
        trunk_dict = {}
        lacp_dict = {}
        poolDict = {}
        nodeDict = {}
        monitorDict = {}
        ifDict = {}
        floatVlanDict = {}
        floatIfDict = {}
        vlanDict = {}
        tmpDict = {}
        long_names_dict = {}
        mng_dict = {'/hprompt': 'ena'}
        ha_dict = { 'peer': []}
        sync_list = []
        to_filter_list = []

    # end of fun

    def fun_clear_monitor_vars():
        if 'hcType' in locals():
            del hcType
        if 'name' in locals():
            del name
        if 'rd' in locals():
            del rd
        if 'inter' in locals():
            del inter
        if 'tmp' in locals():
            del tmp
        if 'ip' in locals():
            del ip
        if 'port' in locals():
            del port

    def fun_parsers_runner(in_name):
        global log1str, log2str
        global to_filter_list

        # print("running health_check_parser")
        x1, x2 = health_check_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running real_parser")
        x1, x2 = real_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running group_parser")
        x1, x2 = group_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        x1, x2 = snat_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running trunk_parser")
        x1, x2 = trunk_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running func_vlan_parser")
        x1, x2 = func_vlan_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running selfip_parser")
        x1, x2 = selfip_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running prof_parser")
        x1, x2 = prof_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        # print("running persist_parser")
        x1, x2 = persist_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        x1, x2 = ltm_policy_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        # print("running func_virt_parser")

        x1, x2 = func_virt_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        if to_filter_list and to_filter_list != []:
            # print('Starting filter convertion!')
            to_filter_list, x1, x2 = filter_parser(to_filter_list)
            for ELEMENT in x1:
                log1str += ELEMENT
                log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
            for ELEMENT in x2:
                log2str += ELEMENT
                log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        x1, x2 = mng_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        x1, x2 = ha_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))

        x1, x2 = route_parser(in_name)
        for ELEMENT in x1:
            log1str += ELEMENT
            log1.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))
        for ELEMENT in x2:
            log2str += ELEMENT
            log2.write('\n###\n%s\n' % ELEMENT.replace('             ', ' '))


    def fun_extract_name (str_name, log_write):
        if '/' in str_name:
            name_split= str_name.split('/')
            if len(name_split) == 3:
                junk, rd, name = name_split
            else:
                rd = name_split[1]
                name = name_split[len(name_split)-1]
                log_write.append(
                ' Object type: Group \n Object name: %s \n Found both Route Domain and what looks like iAPP conifuration! using RD=%s,full object name=%s Please address it manually:\n' % (
                    name, rd, '/'.join(name_split)))
            name = name.replace(' {', '')
        else:
            rd = "Common"
            name = str_name
        return name, rd, log_write

    def fun_port_num_validate(dport):
        try:
            int(dport)
            if dport == "0":
                return 1
            return dport
        except ValueError:
            return dport_dict[dport]

    def fun_loop_mult_val(l):
        return_list = []
        for ind_x, x in enumerate(l):
            if ind_x % 2 == 0:
                return_list.append(str(x) + '##=##' + str(l[ind_x + 1]))
            else:
                continue
        return return_list

    def fun_hc_long_name(hc, name, log_write):
        if len(hc) > 32:
            if hc.replace(' ', '') in long_names_dict:
                hc = long_names_dict[hc.replace(' ', '')]
            else:
                log_write.append(
                    "\n###\n Object type: Group \n Object name: %s \n Issue: Uses unsupported Health Check: %s \n" % (
                        name, hc))
                hc = 'icmp'
        return hc, log_write

    def fun_rd_split(name_split, obj_type, log_write):
        junk=""
        if len(name_split) == 3:
            junk, rd, name = name_split
        else:
            rd = name_split[1]
            name = name_split[len(name_split)-1]
            log_write.append(
            ' Object type: %s \n Object name: %s \n Found both Route Domain and what looks like iAPP conifuration! using RD=%s,full object name=%s Please address it manually:\n' % (
                obj_type, name, rd, '/'.join(name_split)))
        return junk, rd, name, log_write

    #################
    #        #
    #    Nodes    #
    #        #
    #################

    def real_parser(text):
        if len(nodeDict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for node in re.findall('(^ltm node.+{\n(  .+\n)+^})', text, re.MULTILINE):
            for line in ''.join(node[:-1]).splitlines():
                line=line.lstrip()
                if "ltm node" in line:
                    if '/' in line:
                        junk, rd, name = line.split('/')
                        name = name.replace(' {', '')
                    else:
                        name = line[9:].split(' ')[0]
                        rd = 'Common'
                    nodeDict.update({name: {'weight':1}})
                elif "address" in line:
                    junk, ip = line.split('address ')
                    nodeDict[name].update({'rip': ip})
                elif "description" in line:
                    nodeDict[name].update({'name': line[12:].replace('}', '')})
                elif '}' == line:
                    pass
                elif 'monitor' == line.replace(' ', '')[0:7]:
                    if '{' in line and '}' in line:
                        log_write.append(' Object type: Real \n Object name: %s \n Issue: Found multiple healthchecks and did not join them to one LOGEXP please perform manually!\n' % (name))
                    elif '/' in line:
                        junk, rd, hc = line.split('/')
                    else:
                        junk, hc = line[8:].split(' ')

                    hc, log_write = fun_hc_long_name(hc, name, log_write)
                    nodeDict[name].update({'health': hc})
                elif 'session' == line.replace(' ', '')[0:7]:
                    if line.replace(' ', '')[7:]=='user-disabled':
                        nodeDict[name].update({'shut': 'psession'})
                elif line in ["state up"]:
                    pass
                else:
                    log_unhandeled.append(
                        ' Object type: Real\n Object name: ' + name + '\nLine: ' + line.replace(' ', ''))
            if rd != 'Common':
                log_write.append(
                    ' Object type: Real \n Object name: %s \n Issue: Found Route Domain conifuration! using RD=%s, Please address it manually!\n' % (name, rd))
        return log_write, log_unhandeled

    #################
    #        #
    #    Pools     #
    #        #
    #################

    def group_parser(text):
        if len(poolDict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for pool in re.findall('(^ltm pool.+{\n(  .+\n)+^})', text, re.MULTILINE):
            global hc_id
            loglines = []
            tmp_list = []
            tmp_dict = {}
            prioDict={'prio_list':[]}
            new_bkp_group = {}
            strPool = ''.join(pool[:-1])
            for line in strPool.splitlines():
                if "ltm pool" in line:
                    if '/' in line:
                        name_split= line.split('/')
                        if len(name_split) == 3:
                            junk, rd, name = name_split
                        else:
                            rd = name_split[1]
                            name = name_split[len(name_split)-1]
                            log_write.append(
                            ' Object type: Group \n Object name: %s \n Found both Route Domain and what looks like iAPP conifuration! using RD=%s,full object name=%s Please address it manually:\n' % (
                                name, rd, '/'.join(name_split)))
                        name = name.replace(' {', '')
                    else:
                        name = line.replace('ltm pool ', '').split(' ')[0]
                        rd = 'Common'
                elif "monitor " in line:
                    # print(line)
                    if "and" in line:
                        hc = name + '_logexp'
                        hc_descrip = hc[:32]
                        if len(hc) > 32:
                            hc_id += 1
                            long_names_dict.update({hc: hc_id})
                            hc = hc_id
                        monitorDict.update({hc: {'name': hc_descrip, 'hcType': 'logexp', 'advtype': {'expr': ''}}})
                        tmphc = ''
                        for x in line.split(' and '):
                            if '/' in x:
                                name_split = x.split('/')
                                if len(name_split) == 3:
                                    junk, rd, hcname = name_split
                                else:
                                    rd = name_split[1]
                                    hcname = name_split[len(name_split)-1]
                                    log_write.append(
                                    ' Object type: Group \n Object name: %s \n Found both Route Domain and what looks like iAPP conifuration! using RD=%s,full object name=%s Please address it manually:\n' % (
                                        hcname, rd, '/'.join(name_split)))

                                if rd != 'Common':
                                    log_write.append(
                                        ' Object type: Group \n Object name: %s \n Issue: Found Route Domain conifuration! using RD=%s, Please address it manually!\n' % (hcname, tmprd))
                            elif '    monitor ' in x:
                                tmphc = x.replace('    monitor ', '')
                                if tmphc in long_names_dict:
                                    hcname=monitorDict[long_names_dict[tmphc]]['name']
                            else:
                                tmphc = x
                            tmphc= tmphc.strip()
                            tmphc, log_write = fun_hc_long_name(tmphc, hcname, log_write)

                            if monitorDict[hc]['advtype']['expr'] == '':
                                monitorDict[hc]['advtype'].update(
                                    {'expr': monitorDict[hc]['advtype']['expr'] + '(' + str(tmphc) + ')'})
                            else:
                                monitorDict[hc]['advtype'].update(
                                    {'expr': monitorDict[hc]['advtype']['expr'] + '&(' + str(tmphc) + ')'})
                    else:
                        if '/' == line.replace(' ', '')[7]:
                            junk, rd, hc, log_write = fun_rd_split(line.replace(' ', '').split('/'), "Health Check", log_write)
                        else:
                            hc = re.search(r'^\s+monitor (.+)',line).group(1)
                            rd = 'Common'
                        
                        if hc in advhcSupTypes:
                            hc=advhcSupTypes[hc]
                        # print(hc)
                        # print(monitorDict)
                        hc, log_write = fun_hc_long_name(hc, name, log_write)
                        if not (hc in monitorDict or hc in advhcSupTypes):
                            if hc in default_advhc_dict:
                                monitorDict.update({ hc: default_advhc_dict[hc] })
                            else:
                                log_write.append(' Object type: Health Check \n Object name: %s\n Issue: found health check config in group %s that is was not defined (may be default) and not predifind in Global Vars please correct manually!\n' % (hc, name))
                    # print(hc)
                elif "min-active-members" in line:
                    if line.replace(' ','').replace('min-active-members','') != '1':
                        log_write.append(" Object type: Group \n Object name: %s \n Issue: Priority-group activation with non default minimum active members. Please address manually\n " % name)
                elif "description" in line:
                    descrip = line.replace('    description ', '').replace('}', '')
                    # print ("Name="+name+" ,descrip="+descrip)
                elif 'load-balancing-mode' in line:
                    metric = line.replace('    load-balancing-mode ', '')
                    if metric in metricDict:
                        metric = metricDict[metric]
                else:
                    loglines.append(line)
            # print('Name='+name+', hc='+str(hc))
            for member in re.findall('^(    members.+{\n(  .+\n)+^    })', strPool, re.MULTILINE):
                memberTmpDict = {}
                new_group = {}
                prio = '0'
                str_member=''.join(member[:-1])
                rport_flag = 0
                rport = "0"
                for line in str_member.splitlines():
                    if line.replace(' ', '')[0:7] == 'monitor':
                        if "and" in line:
                            hc = name + '_logexp'
                            hc_descrip = hc[:32]
                            if len(hc) > 32:
                                hc_id += 1
                                long_names_dict.update({hc: hc_id})
                                hc = hc_id
                            monitorDict.update({hc: {'name': hc_descrip, 'type': 'logexp', 'advtype': {'expr': ''}}})
                            tmphc = ''
                            for x in line.split(' and '):
                                if '/' in x:
                                    junk, tmprd, tmphc = x.split('/')
                                    if tmprd != 'Common':
                                        log_write.append(' Object type: Group \n Object name: %s\n Issue: Found Route Domain conifuration! using RD=%s, Please address it manually!\n' % (name, tmprd))
                                elif '    monitor ' in x:
                                    tmphc = x.replace('    monitor ', '')
                                else:
                                    tmphc = x

                                tmphc, log_write = fun_hc_long_name(tmphc, name, log_write)

                                if monitorDict[hc]['advtype']['expr'] == '':
                                    monitorDict[hc]['advtype'].update(
                                        {'expr': monitorDict[hc]['advtype']['expr'] + '(' + str(tmphc) + ')'})
                                else:
                                    monitorDict[hc]['advtype'].update(
                                        {'expr': monitorDict[hc]['advtype']['expr'] + '&(' + str(tmphc) + ')'})
                        else:
                            if '/' in line:
                                junk, rd, mon = line.replace(' {', '').split('/')
                            else:
                                mon = re.sub(r'^monitor (.+)', r'\1', line)

                        mon, log_write = fun_hc_long_name(mon, name, log_write)

                        # print(mon)

                        memberTmpDict.update({mNamePort: 'health ' + str(mon)})
                        if "ratio " in str_member:
                            weight=str_member[str_member.index("ratio")+6:str_member.index("\n",str_member.index("ratio"))]
                        else:
                            weight=1
                        mem_name, mem_port=mNamePort.split(':')
                        if mem_name in nodeDict:
                            if nodeDict[mem_name]['weight']!=weight:
                                # print('weight is different! for %s' % mem_name)
                                new_mNamePort = mNamePort.replace(mNamePort,
                                                                  mNamePort.replace(':', '_') + '_' + name)
                                if mNamePort in memberTmpDict:
                                    memberTmpDict.update({new_mNamePort.split(':')[0]: memberTmpDict[mNamePort]})
                                    del memberTmpDict[mNamePort]
                                nodeDict.update({new_mNamePort.split(':')[0]: {'rip': nodeDict[mem_name]['rip'],'health': mon, 'weight':weight, 'maxcon 0 logic': ''}})
                            elif not 'health' in nodeDict[mNamePort.split(':')[0]]:
                                nodeDict[mNamePort.split(':')[0]].update({'health': mon})
                            elif not nodeDict[mNamePort.split(':')[0]]['health'] == mon:
                                new_mNamePort = mNamePort.replace(mNamePort,
                                                                  mNamePort.replace(':','_') + '_' + name)
                                # print(new_mNamePort)
                                if mNamePort in memberTmpDict:
                                    memberTmpDict.update({new_mNamePort: memberTmpDict[mNamePort]})
                                    del memberTmpDict[mNamePort]
                                nodeDict.update({new_mNamePort: {'rip': nodeDict[mem_name]['rip'],'health': mon}})
                        else:
                            if weight!=1:
                                nodeDict.update({mem_name: {'rip': mem_name, 'health': mon}})
                            else:
                                nodeDict.update({mem_name: {'rip': mem_name, 'health': mon, 'weight': weight,'maxcon 0 logic': ''}})
                    # print (memberTmpDict)
                    elif "app-service " == line.replace('  ','')[0:12]:
                        continue
                    elif "/" in line or (":" in line and "{" in line):
                        # print (line)
                        loglines.remove(line)
                        if '/' in line:
                            junk, rd, mNamePort, log_write = fun_rd_split(line.split('/'), "Group", log_write)
                            mNamePort = mNamePort.replace(' {', '')
                        else:
                            mNamePort = line.replace('{', '').replace(' ', '')

                        if rd != 'Common':
                            log_write.append(
                                ' Object type: Group \n Object name: ' + name + ' \n Issue: Found Route Domain conifuration! using RD=%s, Please address it manually!\n')
                        # print('rd='+rd+', mName='+mNamePort+', name='+name)
                        if 'metric' in locals():
                           new_group.update({'advhc': hc, 'metric': metric})
                        else:
                            new_group.update({'advhc': hc, 'metric': 'roundrobin'})
                        if 'members' in new_group:
                            memberTmpDict = new_group['members']
                            memberTmpDict.update({mNamePort: 'health '})
                        else:
                            memberTmpDict.update({mNamePort: 'health '})
                        if not "rport" in locals() and not "donerename" in locals():
                            rport = list(memberTmpDict)[0].split(':')[1]
                        for x in list(memberTmpDict):
                            donerename=0
                            if len(x.split(':')) == 2 and x.split(':')[1] != rport:
                                # print("Found different port, grp:"+name+", Was:"+rport+", Now:"+ x.split(':')[1])
                                rport = list(x.split(':'))[1]
                                rport_flag+=1
                            for y in list(memberTmpDict):
                                passrename=0
                                if len(y.split(':')) == 1 or len(x.split(':')) == 1:
                                    passrename=1

                                if not (passrename) and x.split(':')[1] != y.split(':')[1] and x != y:
                                    donerename=1
                                    
                                    nodeDict.update({ y.replace(':', '_'): nodeDict[y.split(':')[0]].copy() })
                                    nodeDict[y.replace(':', '_')].update({ "addport": y.split(':')[1] })
                                    memberTmpDict[y.replace(":", "_")] = memberTmpDict.pop(y)

                            if donerename and x in memberTmpDict and not("_" in x):
                                nodeDict.update({ x.replace(":", "_"): nodeDict[x.split(':')[0]].copy() })
                                nodeDict[x.replace(":", "_")].update({ "addport": x.split(':')[1] })
                                memberTmpDict[x.replace(":", "_")] = memberTmpDict.pop(x)

                        new_group.update({'members': memberTmpDict})
                        # print('rd=' + rd + ', mName=' + mNamePort + ', name=' + name)
                        # print(new_group)
                    # print(memberTmpDict)
                    elif "address" in line:
                        # print(line)
                        loglines.remove(line)
                        junk, ip = line.split('address ')
                        if not mNamePort.split(':')[0] in nodeDict:
                            mNamePort_found=0
                            log_write.append(" Object type: Group \n Object name: " + name + "\n Issue: Node not found or ip missmatch! Please check manually for %s\n" %mNamePort.split(':')[0])
                        else:
                            mNamePort_found=1
                        # print('name='+name+', IP='+ip)
                    elif line.replace(' ','')[0:11] == "description":
                        member_descript=line[line.index("description")+12:]
                        if not '"' in member_descript:
                            member_descript=("\"%s\"" % member_descript)
                        try:
                            if mNamePort.split(':')[0] in nodeDict:
                                if 'name' in nodeDict[mNamePort.split(':')[0]]:
                                    if nodeDict[mNamePort.split(':')[0]]['name'] != member_descript:
                                        log_write.append(" Object type: Group \n Object name: " + name + "\n Issue: Node description (%s) is different from group member description (%s)! please check manually\n" % (nodeDict[mNamePort.split(':')[0]]['name'], member_descript))
                                else:
                                    nodeDict[mNamePort.split(':')[0]].update({'name': member_descript})
                            else:
                                log_write.append(" Object type: Group \n Object name: " + name + "\n Issue: Node not found! Please check manually for %s\n" % mNamePort.split(':')[0])
                        except Exception as e:
                            raise e
                    elif "priority-group" in line:
                        loglines.remove(line)
                        prio = list(filter(None, line.split()))[1]
                        prioDict.update({mNamePort: prio})
                        if not prio in prioDict['prio_list']:
                            prioDict['prio_list'].append(prio)
                    elif line.replace('}', '').replace(' ', '').replace('{', '').replace('members', '') != '':
                        try:
                            loglines.remove(line)
                        except Exception as e:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            print("Encountered an error while correcting log for group members, error on line %d" % exc_tb.tb_lineno)
                        if line[0] == '}':
                            continue
                if rport_flag==1:
                    rport_dict.update({name: rport})
                poolDict.update({name: new_group})
                if "descrip" in locals() and descrip != "":
                    # print (name)
                    poolDict[name].update({'name': descrip})
                    del descrip
                del rport
                if prioDict['prio_list'] != []:
                    new_bkp_group = copy.deepcopy(poolDict[name])
                    if len(prioDict['prio_list']) == 1 and len(poolDict[name]['members']) == (len(prioDict)-1):
                        pass
                    elif len(prioDict['prio_list']) == 1 and len(poolDict[name]['members']) != (len(prioDict)-1):
                        for member in list(poolDict[name]['members']):
                            if member in prioDict:
                                del poolDict[name]['members'][member]
                            else:
                                del new_bkp_group['members'][member]
                        poolDict[name].update({'backup': 'g' + name + '_bkp'})
                        poolDict.update({name + '_bkp': new_bkp_group})
                    elif len(prioDict['prio_list']) == 2 and len(poolDict[name]['members']) == (len(prioDict)-1):
                        max_val = sorted(prioDict['prio_list'], reverse=True)[0]
                        for member in list(new_group['members']):
                            if member in prioDict and prioDict[member] == max_val:
                                del poolDict[name]['members'][member]
                            elif member in prioDict:
                                del new_bkp_group['members'][member]
                            else:
                                log_unhandeled.append(
                                    'Unhandled exception in priority-group to backup convertion! Please check manually')
                        poolDict[name].update({'backup': 'g' + name + '_bkp'})
                        poolDict.update({name + '_bkp': new_bkp_group})
                    else:
                        log_write.append(
                            " Object type: Group \n Object name: %s \n Issue: Priority-group with more then 2 groups is being used. Please address manually\n " % name)
            for line in loglines:
                if line[0] == '}':
                    continue
                if line.replace('}', '').replace(' ', '').replace('{', '').replace('members', '') != '':
                    log_unhandeled.append(' Object type: Group\n Object name:' + name + '\n Line: ' + line)

        # end of member
        return log_write, log_unhandeled

    #########################
    #                        #
    #    Health Checks        #
    #                        #
    #########################

    def health_check_parser(text):
        global hc_id
        if len(monitorDict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for monitor in re.findall('(^ltm monitor.+{\n(  .+\n)+^})', text, re.MULTILINE):
            strMonitor = ''.join(monitor[:-1])
            x1, x2 = strMonitor.splitlines()[0].replace('ltm monitor ', '').replace('Common', '').split(' ')[0:2]
            if x1 == x2:
                log_unhandeled.append(
                    ' Object type: Health Check\n Object name: %s \n Issue: This is a default object, Skipping the conversion in case needed please address manually\n' % x1)
                continue
            elif not x1 in advhcSupTypes:
                log_unhandeled.append(
                    ' Object type: Health Check\n Object name: %s \n Issue: This object is not currently supported, please update script or address manually\n' % x1)
                continue
            new_hc = {}
            if x1.lower() == 'radius':
                new_hc.update({'type':'auth'})
            elif x1.lower() == 'radius_accounting' or x1.lower() == 'radius-accounting':
                new_hc.update({'type':'account'})
            elif x1 == 'ldap':
                if "username" in strMonitor and "password" in strMonitor and "base" in strMonitor:
                    for x in ["username", "password", "base"]:
                        globals()[x] = strMonitor[strMonitor.index(x)+9:strMonitor.index('\n',strMonitor.index(x))]
                        strMonitor=strMonitor[0:strMonitor.index(x)]+strMonitor[strMonitor.index('\n',strMonitor.index(x)):]
                    new_hc.update({'advtype':{'bind': ("%s %s %s" % (base, username, password))}})
            del x1, x2
            fun_clear_monitor_vars()
            for line in strMonitor.splitlines():
                if "ltm monitor" in line:
                    line = line.replace(' {', '').replace('ltm monitor ', '')
                    hcType, name = line.split(' ')
                    name, rd, log_write = fun_extract_name(name, log_write)
                    if rd != 'Common':
                        log_write.append(
                            ' Object type: Health Check \n Object name: %s \n Found Route Domain conifuration! using RD=%s, Please address it manually:\n' % (
                                name, rd))
                        pass
                    descrip = name
                    if len(name) > 32:
                        hc_id += 1
                        log_write.append(
                            ' Object type: Health Check \n Object name: %s \n Issue: Name too long, changed to ID : %s\n' % (
                                name, hc_id))
                        long_names_dict.update({name: hc_id})
                        name = hc_id
                    new_hc.update({'hcType': advhcSupTypes[hcType], 'advtype': {}, 'name': '"' + descrip[:32] + '"'})
                elif "interval" in line:
                    inter = line.split('interval ')[1]
                    new_hc.update({'inter': inter})
                elif 'time-until-up 0' in line:
                    pass
                elif "timeout" in line:
                    tmp = line.split('timeout ')[1]
                    # print('name=%s,inter=%s, retry=%d, timeout=%s' % (name, inter, int(tmp)/int(inter), tmp))
                    new_hc.update({'retry': int(int(tmp) / int(inter))})
                    new_hc.update({'timeout': inter})
                elif "destination" in line:
                    line = line.replace('    ', '')
                    # print('line='+line)
                    line = line.replace('destination ', '')
                    if ':' in line:
                        ip, port = line.split(':')
                    elif '.' in line:
                        ip, port = line.split('.')
                    if ip != "*":
                        new_hc.update({'dest': ip})
                    if port != "*":
                        new_hc.update({'dport': port})
                elif "send " in line:
                    if line != '    send none' :
                        if hcType == 'udp':
                            log_write.append(' Object type: Health Check \n Object name: %s \n Issue: Sending string is not supported in UDP Health Checks.' % name)
                        if hcType in ['http', 'https']:
                            if ' send "' in line:
                                line = line[line.index(' send "')+7:]
                            else:
                                line = line[line.index(' send ')+6:]
                            
                            if line.split(' ')[0] in ["GET", "POST", "PUT", "HEAD"]:
                                method = line.split(' ')[0]
                                path = line.split(' ')[1]
                            else: 
                                method = "GET"
                                path = line.split(' ')[0]
                            
                            if path[len(path) - 1] == '"':
                                path = path[:len(path) - 1]
                            if path[len(path) - 1] == 'n' and path[len(path) - 2] == '\\':
                                path = path[:len(path) - 2]
                            if path[len(path) - 1] == 'r' and path[len(path) - 2] == '\\':
                                path = path[:len(path) - 2]
                            if "HTTP/1." in path:
                                path = path[:path.index("HTTP/1.")]
                            line = line[line.index(path) + len(path):]
                            # print('method='+method+', path='+path)
                            new_hc['advtype'].update({'method': method})
                            new_hc['advtype'].update({'path': '"' + path + '"'})
                            tmp = line.split('\\r\\n\\r\\n')
                            for header in tmp[0].split('\\r\\n'):
                                tmpHeader = header.replace('\\r', '').replace('\\n', '').replace('\\', '').replace('"','').replace(' ', '')
                                # print (tmpHeader)
                                tmpHDR = ''
                                if "host:" in header.lower():
                                    host = header.replace(' ', '').split(':')[1]
                                    new_hc['advtype'].update({'host': '"' + host + '"'})
                                # print('host='+host)
                                elif tmpHeader in ['', '"', 'HTTP/1.1', 'HTTP/1.0', ' HTTP/1.1', ' HTTP/1.0', 'HTTP/1.1 ','HTTP/1.0 ']:
                                    pass
                                else:
                                    k, v = header.split(':')
                                    # print('header name=%s, value=%s' % (k,v))
                                    if 'header' in new_hc['advtype']:
                                        tmpHDR = new_hc['advtype']['header'].replace('\\r\\n\n...','')
                                        tmpHDR = tmpHDR + '\n' + k + ':' + v
                                    else:
                                        tmpHDR = '\n' + k + ':' + v
                                    tmpHDR += '\\r\\n\n...'
                                    new_hc['advtype'].update({'header': tmpHDR})
                            if method.lower() == "post":
                                body = tmp[1].replace('\\r\\n"', '')
                                # print('body='+body)
                                new_hc['advtype'].update({'body': '"' + body + '"'})
                        else:
                            # new_hc['advtype']=line
                            new_hc['advtype'].update({'send': line.replace('    send ', '')})
                elif "recv " in line:
                    if line != '    recv none' :
                        if hcType == 'udp':
                            log_write.append(' Object type: Health Check \n Object name: %s \n Issue: Sending string is not supported in UDP Health Checks.' % name)
                        if hcType in ['http', 'https']:
                            line = line.replace('    recv ', '')
                            # print ("response="+line)
                            if line == '"200 OK"':
                                new_hc['advtype'].update({'response': '200 none'})
                            else:
                                if not line.replace('    response ', '')[0] == '"':
                                    # print ('/'+line.replace('    response ', '')+'/')
                                    response_string = '"' + line.replace('    response ', '') + '"'
                                else:
                                    # print ('/'+line.replace('    response ', '')+'/')
                                    response_string = line.replace('    response ', '')
                                new_hc['advtype'].update({'response': '200 inc ' + response_string})
                        else:
                            # log_write.append('please exemin:\n/c/slb/advhc/%s SCRIPT/script/expect %s\n' % (name, line.replace('    recv ', '')))
                            new_hc['advtype'].update({'expect': line.replace('    recv ', '')})
                elif "recv-disable" in line:
                    if line != '    recv-disable none' :
                        log_write.append(' Object type: Health Check \n Object name: %s \n Issue: disable string isnt currently supported.' % name)
                elif 'cipherlist' in line:
                    new_hc.update({'cipher': '"' + line.replace('    cipherlist ', '') + '"', 'ssl': 'ena'})
                elif 'ip-dscp 0' in line or 'defaults-from' in line or 'debug no'==line.replace('  ','') or "adaptive disable" in line:
                    ignore = 1
                elif 'compatibility enabled' in line and hcType == 'https':
                    new_hc.update({'cipher': '"ALL"'})
                elif line.replace(' ','')[0:11] == "description":
                    new_hc.update({'name':line[12:]})
                elif line.replace(' ','')[0:11] == "app-service" or line.replace(' ', '')=="}" or line.replace(' ','')=='':
                    pass
                else:
                    # print(name, hcType ,line)
                    if hcType in advhcSupTypes:
                        log_unhandeled.append(' Object type: Health Check\n Object name: %s\n Line: %s\n' % (
                            str(name), line.replace('  ', '')))

                monitorDict.update({name: new_hc})
        return log_write, log_unhandeled

    #########################
    #                        #
    #        Prpfiles           #
    #                        #
    #########################

    def prof_parser(text):
        global compres_id
        if len(profDict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for profile in re.findall('(^ltm profile.+{\n(  .+\n)+^})', text, re.MULTILINE):
            str_profile = ''.join(profile[:-1])
            prof = str_profile.splitlines()[0].replace('ltm profile ', '').replace(' {', '')
            # print(prof)
            if '/' in prof:
                # profType, rd, name = prof.replace(' ', '').split('/')
                profType, rd, name, log_write = fun_rd_split(prof.replace(' ', '').split('/'), "Group", log_write)
            else:
                profType, name = prof.replace('  ', '').split(' ')
                rd = 'Common'
            profDict.update({name: {'type': profType, 'adv': {}}})
            # print(profType)

            if profType == 'http':
                for line in str_profile.splitlines():
                    if 'insert-xforwarded-for' in line:
                        profDict[name].update({'adv': {'/http/xforward': 'ena'}})
            elif profType == 'http-compression':
                profName = name
                if len(profName) > 31:
                    compres_id += 1
                    log_write.append(
                        ' Object type: Compression Profile \n Object name: %s \n Issue: Name is too long, changed to ID: %d\n' % (
                            name, compres_id))
                    long_names_dict.update({profName: compres_id})
                    profName = compres_id
                compres_dict.update({profName: {'virt': []}})
                for line in str_profile.splitlines():
                    if 'content-type-include' in line:
                        compres_dict[profName].update(
                            {'brwslist': list(filter(None, line.replace('content-type-include {', '').split()))[:-1]})
            # Continue Profile Parser!
            if rd != 'Common':
                log_write.append(
                    ' Object type: Profile \n Object name: %s \n Issue: Found Route Domain conifuration! using RD=%s, should have been migrated to common but validate manually!\n' % (
                        name, rd))
        return log_write, log_unhandeled

    #########################
    #            #
    #    persist     #
    #            #
    #########################

    def persist_parser(text):
        if len(persist_dict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for persist in re.findall('(^ltm persistence.+{\n(  .+\n)+^})', text, re.MULTILINE):
            for line in ''.join(persist[:-1]).splitlines():
                line = line.replace('  ', '')
                if "ltm persistence" in line:
                    line = line.replace('ltm persistence ', '').replace(' {', '')
                    # print(line)
                    if '/' in line:
                        linesplit=line.split('/')
                        lenlinesplit=len(linesplit)
                        persistType=linesplit[0]
                        rd = linesplit[1]
                        name = linesplit[lenlinesplit-1]
                    else:
                        persistType, name = line.split(' ')
                        rd = 'Common'
                    persistType = persistType.replace(' ', '')
                    if persistType == 'source-addr':
                        persistType = 'clientip'
                    persist_dict.update({name: {'type': persistType}})
                elif 'timeout' in line:
                    persist_dict[name].update({'timeout': int(int(line.replace('timeout ', '')) / 60)})
                elif 'cookie-name' in line:
                    persist_dict[name].update({'cookie-name': line.replace('cookie-name ', '')})
                elif 'method' in line:
                    persist_dict[name].update({'method': line.replace('method ', '')})
                elif 'expiration' in line and line.replace('expiration ','')!='0':
                    exp_list=line.replace('expiration ','').split(':')
                    if len(exp_list)==4:
                        exp=int(exp_list[0])*86400
                        del exp_list[0]
                    if len(exp_list)==3:
                        exp=int(exp_list[0])*3600
                        del exp_list[0]
                    if len(exp_list) == 2:
                        exp+=int(exp_list[0])*60
                        del exp_list[0]
                    exp+=int(exp_list[0])
                    log_write.append(' Object type: Persistance \n Object name: %s Please validate expiration, was %s now %d!\n' % (name, line.replace('expiration ',''), exp))
                    persist_dict[name].update({'cookie-AS': 'ena', 'expiration': exp})
                # else:
                #     print(line)

            # Continue Profile Parser!
            if rd != 'Common':
                log_write.append(
                    ' Object type: Group \n Object name: %s Found Route Domain conifuration! using RD=%s, Please address it manually!\n' % (
                        name, rd))
        return log_write, log_unhandeled

    #################
    #                #
    #    Virts       #
    #                #
    #################

    def func_virt_parser(text):
        global to_filter_list
        if len(virt_dict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for virt in re.findall('(^ltm virt.+{\n(  .+\n)+^})', text, re.MULTILINE):
            del_virt = 0
            strVirt = ''.join(virt[:-1])
            if "ltm virtual-address" in strVirt:
                continue

            firstline = virt[0].splitlines()[0].replace(' {', '')
            if '/' in firstline:
                # junk, rd, name = firstline.split('/')
                junk, rd, name, log_write = fun_rd_split(firstline.split('/'), "virt", log_write)
            else:
                junk, name = firstline.replace('ltm virtual', '').split(' ')
            virt_dict.update({name: {'adv': {}, 'service': {}, 'profiles': {}}})

            strProf = ''
            for prof in re.findall('^(    profiles.+{\n(.+\n)+.+}\n    }\n|^    profiles.+{\n.+}\n    }\n)', strVirt,
                                   re.MULTILINE):
                strProf = ''.join(prof[:-1])
            ## Need to complete iRules!!

            strSnat = ''
            if '    source-address-translation {' in strVirt:
                strSnat = re.search(r'(    source-address-translation {\n([^}]+\n)+    })', strVirt).group(0)
                for line in strSnat.replace('  ', '').splitlines()[1:-1]:
                    x, y = line.split(' ')
                    if x == 'type':
                        if y == 'mode automap':
                            log_unhandeled.append(
                                ' Object type: Virt\n Object name: %s \n SNAT Automap is used, please address manually!\n' % name)
                    # virtDict[name]['service'].update({'pip mode': y})
                    elif x == 'pool':
                        if "/" in y:
                            virt_dict[name].update({ 'pip': { 'mode':'nwclss', 'nwclss v4': y.split('/')[2]+" persist disable" } })
                        else:
                            virt_dict[name].update({ 'pip': { 'mode':'nwclss', 'nwclss v4': y+" persist disable" } })

            strPersist = ''
            if '    persist {' in strVirt:
                strPersist = re.search(r'(    persist {\n(.+\n)*?        }\n    })', strVirt).group(0)
            # strPersist=re.findall('^(    persist {\n([^}]+\n)+        }\n    })', strVirt, re.MULTILINE)[0][0]
            ## Need to complete Persistance!!

            str_rules = ''
            if '    rules {' in strVirt:
                str_rules = re.search(r'(.+rules \{(.*\n)+    \})', strVirt).group(0)
                if len(re.findall('}', str_rules)) > 1:
                    str_rules = str_rules[:str_rules.index('    }') + 5]
            ## Need to complete iRules!!

            str_policy = ''
            arr_policy = []
            if '    policies {' in strVirt:
                str_policy = re.search(r'( +policies \{((.*\n)*?)    \})', strVirt).group(2)
                # if len(re.findall('}', str_policy)) > 1:
                #     str_policy = str_policy[:str_policy.index('    }') + 5]
                for pol in str_policy.replace('  ','').replace(' { }','').splitlines():
                    if pol == "":
                        continue
                    elif "/" in pol:
                        pol=pol.split('/')
                        rd = pol[1]
                        pol = pol[len(pol)-1] 
                        if rd != "Common":
                            log_write.append("Route domain is used in object %s, please verify!" % pol)
                    arr_policy.append(pol)
                virt_dict[name].update({'cntclss':{}})
                for x in arr_policy:
                    if x in cntrule_dict:
                        for cntrulename in cntrule_dict[x]:
                            for ruleid in cntrule_dict[x][cntrulename]:
                                if not 'cntclss' in cntrule_dict[x][cntrulename][ruleid]:
                                    log_write.append(' Object type: LTM Policy \n Object name: %s \n Issue: did not get condition, please convert manually.\n' % x)
                                    continue
                                virt_dict[name]['cntclss'].update({'cntrules '+ruleid:{}})
                                for y in cntrule_dict[x][cntrulename][ruleid]:
                                    virt_dict[name]['cntclss']['cntrules '+ruleid].update({y: cntrule_dict[x][cntrulename][ruleid][y]})
                    else:
                        log_write.append(' Object type: LTM Policy \n Object name: %s \n Issue: Was not parsed, please convert manually.\n' % x)

            strVirt=strVirt.replace(str_policy,'')

            ## Need to complete iRules!!
            
            strVirtVlan = ''
            if '    vlans {' in strVirt:
                vlansflag=1
                strVirtVlan = re.search(r'(.+vlans \{(.*\n)+.+vlans-.+)', strVirt).group(0)
                log_unhandeled.append(
                    ' Object type: Virt \n Object name: ' + name + '\n Issue: Vlan specific virt is not supported, please address manyally:\n' + strVirtVlan)

            strVirt = strVirt.replace(strPersist, '').replace(strSnat[:-1], '').replace(strProf, '').replace(str_rules,
                                                                                                             '').replace(
                strVirtVlan, '')
            strProf = re.sub(r'        (.+)\{\n            (.+)\n        \}', r'\1#=#\2', strProf).replace('  ',
                                                                                                           '').replace(
                'profiles {\n', '')
            strProf = strProf.replace(' #=#context ', '#=#').replace(' { }', '#=#general')
            strPersist = re.sub(r'        (.+)\{\n            (.+)\n        \}', r'\1#=#\2', strPersist).replace('  ',
                                                                                                                 '').replace(
                'persist {\n', '')
            strPersist = strPersist.replace(' #=#', '#=#').replace('}', '')
            if "vlans-disabled" in strVirt:
                strVirt = re.sub(r'\s+vlans-disabled', '', strVirt)

            for line in strVirt.splitlines():
                if 'mask' in line:
                    if line.split('    mask ')[1] != '255.255.255.255':
                        log_unhandeled.append(
                            ' Object type: Virt \n Object name: ' + name + '\n Issue: Virt destination is not /32, will try to convert to filter. please make sure manyally:\n' + ''.join(
                                virt[:-1]) + '\n')
                        to_filter_list.append(''.join(virt[:-1]))
                        del_virt = 1
                elif 'ltm virtual' in line or line.replace('  ', '') in ['}', '', 'translate-address enabled',
                                                                         'translate-port enabled']:
                    continue
                elif 'destination' in line:
                    if '/' in line:
                        junk, rd, vip = line.split('/')
                    else:
                        junk, vip = line.replace('  ', '').split(' ')
                    aplic = 'basic-slb'
                    if len(vip.split(':')) > 2:
                        log_unhandeled.append(' Object type: Virt \n Object name: ' + name + '\n Issue: IPv6 VIP found, currently unsupported. please address manually\n' + vip)
                        vip, dport = vip.split('.')
                    else:
                        vip, dport = vip.split(':')
                    dport = fun_port_num_validate(dport)
                    if "%" in vip:
                        log_unhandeled.append(' Object type: Virt \n Object name: ' + name + '\n Issue: Route domain configuration in VIP listener! will omit please make sure logic retained:\n' + vip)
                        vip = vip.split('%')[0]
                    virt_dict[name].update({'vip': vip, 'dport': dport})
                    if str(dport) == "1":
                        aplic = "ip"
                    elif str(dport) == "80":
                        aplic='http'
                    elif str(dport) == "443":
                        aplic = 'ssl'
                # VIP + PORT
                elif 'source ' in line:
                    source = ''.join(line.split('    source '))
                    if source == '0.0.0.0/0':
                        continue
                    else:
                        virt_dict[name].update({'source': source})
                elif 'ip-protocol' in line:
                    virt_dict[name].update({'proto': ''.join(line.split('    ip-protocol '))})
                elif '    pool ' in line:
                    grp_name, junk, log_write = fun_extract_name(line.split('    pool ')[1], log_write)
                    virt_dict[name]['service'].update({'group': grp_name})
                    if grp_name in rport_dict:
                        virt_dict[name]['service'].update({'rport': rport_dict[grp_name]})
                    else:
                        virt_dict[name]['service'].update({'rport': '0'})
                elif 'description' in line:
                    virt_dict[name].update({'name': ''.join(line.replace('  ', '').split('description '))})
                elif 'mirror' in line:
                    virt_dict[name]['service'].update({'mirror': 'ena'})
                elif 'vs-index' in line:
                    continue
                elif line == '    disabled':
                    virt_dict[name].update({'disable': ' '})
                else:
                    log_unhandeled.append(
                        ' Object type: Virt\n Object name: %s \n Line: %s\n' % (name, line.replace('  ', '')))
            for line in strProf.splitlines():
                if '/' in line:
                    junk, rd, prof, log_write = fun_rd_split(line.split('/'), "profile", log_write)
                elif '}' == line:
                    continue
                else:
                    prof = line
                profName, context = prof.split('#=#')
                profType = ''
                if profName in profDict:
                    profType = profDict[profName]['type']
                    for z in profDict[profName]['adv']:
                        virt_dict[name]['adv'].update({z: profDict[profName]['adv'][z]})
                    if profType == 'http-compression':
                        if profName in long_names_dict:
                            profName = long_names_dict[profName]
                        compres_dict[profName]['virt'].append(str(name) + '##=##' + str(dport))
                elif profName in defProfDict:
                    profType = defProfDict[profName]
                else:
                    log_write.append(
                        ' Object type: Profile \n Object name: %s \n Issue: Profile is not found in both config and default profile list.\n' % profName)
                virt_dict[name]['profiles'].update({profName: {'type': profType, 'context': context}})
                # print('virt='+name+', profType='+profType+', aplic='+aplic)
                if profType == 'http' and aplic == 'basic-slb':
                    aplic = 'http'
                elif profType == 'http' and aplic == 'ssl':
                    aplic = 'https'
                elif profType in ['client-ssl', 'server-ssl'] and aplic == 'basic-slb':
                    aplic = 'ssl'
                elif profType in ['client-ssl', 'server-ssl'] and aplic == 'http':
                    aplic = 'https'
                virt_dict[name].update({'aplic': aplic})
                if profType == 'client-ssl':
                    virt_dict[name].update({'ssl': {'fe': 'ena'}})
                elif profType == 'server-ssl':
                    virt_dict[name].update({'ssl': {'be': 'ena'}})

            for line in strPersist.splitlines():
                if not line:
                    continue
                if '/' in line:
                    junk, rd, persistName, log_write = fun_rd_split(line.split('/'), "Persist", log_write)
                else:
                    persistName = line
                persistName, atrib = persistName.split('#=#')
                if atrib == 'default yes':
                    if persistName in persist_dict:
                        virt_dict[name]['persist'] = persist_dict[persistName]
                    elif persistName in defPersistDict:
                        virt_dict[name]['persist'] = defPersistDict[persistName]
                    else:
                        log_write.append(
                            ' Object type: Virt \n Object name: %s \n Issue: required unknown persistance profile: %s, please address manually\n' % (
                                name, line.replace('#=#',' {')+"}"))
                else:
                    log_unhandeled.append(' Object type: Virt \n Object name: %s \n Line: %s\n' % (name, line))
                if 'persist' in virt_dict[name] and virt_dict[name]['persist']['type'] == 'ssl':
                    virt_dict[name].update({'aplic': 'ssl'})
            if del_virt:
                del virt_dict[name]
        return log_write, log_unhandeled

    #################
    #        #
    #    Vlans    #
    #        #
    #################

    def func_vlan_parser(text):
        if len(vlanDict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for vlan in re.findall('(^net vlan .+{\n(  .+\n)+^})', text, re.MULTILINE):
            str_vlan = ''.join(vlan[:-1])
            if_list = []
            tmpDict = {}
            for line in str_vlan.splitlines():
                if "net vlan" in line:
                    if '/' in line:
                        junk, rd, name, log_write = fun_rd_split(line.replace(' {', '').split('/'), "Vlan", log_write)
                    else:
                        name = line.replace(' {', '').replace('net vlan ', '').split()[0]
                        rd = 'Common'
                elif "tag " in line:
                    junk, vid = line.split('tag ')
                else:
                    loglines.append(line)
            if rd != 'Common':
                log_write.append(' Object type: Vlan \n Object name: %s \n Found Route Domain conifuration! using RD=%s, Please address it manually!\n' % (name, rd))

            if "tag-mode" in str_vlan:
                tagmode = re.search(r' +tag-mode.+\n', str_vlan).group(0)
                str_vlan=str_vlan.replace(tagmode, '')
                log_write.append(' Object type: Vlan \n Object name: %s \n tag-mode (%s) command is not supported, Please address it manually!\n' % (name, tagmode))

            try:
                if "interfaces" in str_vlan:
                    inter = ''.join(str_vlan[str_vlan.index('  interfaces {'):str_vlan.index('\n    }\n', str_vlan.index(
                        '  interfaces {'))].splitlines()[1:])
                    inter = inter.replace('  ','').replace('{ }', '{ untagged }').replace('}', '')
                    inter = list(filter(None, re.split(r'{| ', inter)))
                    
                    for port in fun_loop_mult_val(inter):
                        port = port.split('##=##')
                        port[0] = port[0].replace(' ', '')
                        if port[1] == 'untagged':
                            tag = 'untagged'
                        else:
                            tag = 'tagged'

                        if port[0] in trunk_dict:
                            if_list.extend(trunk_dict[port[0]]['members'])
                        elif port[0] in lacp_dict:
                            if_list.extend(lacp_dict[port[0]]['port'])
                        else:
                            if_list.append(port[0])
                        if tag == 'tagged' and not inter[0] in taggedPorts:
                            if port[0] in trunk_dict:
                                taggedPorts.extend(trunk_dict[port[0]]['members'])
                            elif inter[0] in lacp_dict:
                                taggedPorts.extend(lacp_dict[port[0]]['port'])
                            else:
                                taggedPorts.extend(port[0])
                else:
                    if_list=['1']
                
                vlanDict.update({name: {'tag': vid, 'interfaces': if_list}})
                    
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print("Encountered an error while parsing VLAN, error on line %d, Error=%s" % (exc_tb.tb_lineno, e))
                # pass

        return log_write, log_unhandeled

    # for ifs in re.findall('^( {4}interfaces.+)', str_vlan, re.MULTILINE):
    #    ifs=''.join(ifs)
    #    #print('was'+ifs)
    #    if "tagged" in ifs:
    #        port, tag = re.sub(r'.+interfaces.+\{\n( )+(.+) \{\n( )+(.+)\n.+\}\n.+\n',r'\2#=#\4', ifs).split('#=#')
    #    else:
    #        port = re.sub(r'.+interfaces.+\{\n( )+(.+) \{ \}\n.+',r'\2', ifs)
    #        tag='untagged'
    #    if_list.append(port)

    # vlanDict.update( {name: {'tag': vid, 'interfaces': if_list}} )

    #########################
    #            #
    #    Interface IP     #
    #            #
    #########################

    def selfip_parser(text):
        global if_id
        if len(ifDict.keys()) != 0 and len(floatIfDict.keys()) != 0:
            return [], []

        log_write = []
        log_unhandeled = []

        for selfip in re.findall('(^net self .+{\n(  .+\n)+^})', text, re.MULTILINE):
            isSelf = 0
            tmpDict = {}
            strSelfIp = ''.join(selfip[:-1])
            if 'local-only' in strSelfIp:
                if_id += 1
                isSelf = 1

            strPortLD = ''
            if '    allow-service {' in strSelfIp:
                strPortLD = re.search(r'( {4}allow-service \{(.*\n)+ {4}\}\n)', strSelfIp).group(0)
                if strPortLD.replace(' ','') == "allow-service{\ndefault\n}\n":
                    strSelfIp = strSelfIp.replace(strPortLD, '')
                    strPortLD = "allow-service { default } "
                if strPortLD.replace(' ','') == "allow-service{\nall\n}\n":
                    strSelfIp = strSelfIp.replace(strPortLD, '')
                    strPortLD = ""
            strSelfIp = strSelfIp.replace(strPortLD, '')
            for line in strSelfIp.splitlines():
                if "net self" in line:
                    if '/' in line:
                        junk, rd, name, log_write = fun_rd_split(line.replace(' {', '').split('/'), "L3 If", log_write)
                        # junk, rd, name = line.replace(' {', '').split('/')
                    else:
                        name = line.replace('net self ', '').replace(' {', '')
                        rd = 'Common'
                # print('rd='+rd+', name='+name)
                elif "address" in line:
                    junk, ip = line.split('address ')
                    address, mask = ip.split('/')
                    mask = prefixToMaskDict[mask]
                    tmpDict.update(dict(addr=address))
                    tmpDict.update(dict(mask=mask))
                # print('address='+address+', mask='+mask)
                elif "vlan" in line:
                    if '/' in line:
                        junk, rd, vlan, log_write = fun_rd_split(line.replace(' {', '').split('/'), "Vlan", log_write)
                        # junk, rd, vlan = line.split('/')
                    else:
                        vlan = line.replace('vlan', '').replace(' ', '')
                    if not vlan in vlanDict:
                        log_write.append(" Object type: Vlan \n Object name: %s \n Issue: Vlan Not Found! Please address manually\n" % vlan)
                        tmpDict.update(dict(vlan='error:'+vlan))
                    else:
                        tmpDict.update(dict(vlan=vlanDict[vlan]['tag']))
                # print('rd='+rd+', vlan='+vlan)
                elif "traffic-group" in line:
                    tg_str=re.search(r'traffic-group (/.+/)?(.+)', line).group(2)
                    if "traffic-group-local-only"!=tg_str and "traffic-group-1"!=tg_str:
                        log_unhandeled.append(' Object type: L3 Interface \n Object name: %s \n Line: %s\n' % (
                        name, line.replace('  ', '')))
                elif line == '\n' or line == '}':
                    continue
                else:
                    log_unhandeled.append(' Object type: L3 Interface \n Object name: %s \n Line: %s\n' % (name, line.replace('  ', '')))

                if rd != 'Common':
                    log_write.append(
                        ' Object type: Vlan \n Object name: %s \n Issue: Found Route Domain conifuration! using RD=%s, Please address it manually!\n' % (
                            name, rd))

            # end of lines loop
            if isSelf:
                tmpDict.update({'if_id': if_id})
                ifDict.update({name: tmpDict})
                if not vlanDict[vlan]['tag'] in floatVlanDict:
                    floatVlanDict.update({vlanDict[vlan]['tag']: str(if_id)})
            else:
                floatIfDict.update({name: tmpDict})
            if strPortLD != '':
                log_write.append(' Object type: L3 Interface \n Object name: %s \n Issue: Port Lockdown is not currently supported, Please address manually!\n%s\n' % (
                    name, strPortLD))
        return log_write, log_unhandeled

    #################
    #               #
    #   Management  #
    #               #
    #################

    def mng_parser(text):
        tmp = ''

        log_write = []
        log_unhandeled = []
        try:
            mng_dict.update({'mmgmt': {}})
            mng_ip, mng_mask = re.search(r'(sys management-ip (.+) {)', text).group(0).replace('sys management-ip ',
                                                                                                 '').split('/')
            mng_mask = prefixToMaskDict[mng_mask.split(' ')[0]]
            mng_dict['mmgmt'].update({'addr': mng_ip, 'mask': mng_mask})
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # print("Encountered an error while parsing management ip, error on line %d, %s" % (exc_tb.tb_lineno,e))

        if "sys management-dhcp" in text:
            mng_dict['mmgmt'].update({'dhcp': 'ena'})
                
        for mng_route in re.findall('(^sys management-route.+{\n(  .+\n)+^})', text, re.MULTILINE)[:-1]:
            for line in ''.join(mng_route[:-1]).splitlines():
                # print(line)
                if "sys management-route" in line:
                    line = line.replace('sys management-route ', '').replace(' {', '')
                    if '/' == line[0]:
                        junk, rd, name, log_write = fun_rd_split(line.split('/'), "Vlan", log_write)
                        # junk, rd, name = line.split('/')
                    else:
                        name = line.split(' ')[0]
                        rd = 'Common'

                elif "network" == line.replace('  ', '')[0:7]:
                    line = line.replace('  ', '')
                    if 'default' in line:
                        net = 'default'
                    else:
                        junk, net = line.split(' ')
                        net = net.replace(net.split('/')[1], prefixToMaskDict[net.split('/')[1]])
                        net = net.replace('/', ' ')
                elif "gateway" in line:
                    gw = line.replace('  ', '').split(' ')[1]
                elif not line == "}":
                    log_unhandeled.append(
                        ' Object type: Route \n Object name: ' + name + '\n Line: ' + line.replace('  ', ''))
            if net == 'default':
                mng_dict['mmgmt'].update({'gw': gw})
            else:
                log_write.append(
                    ' Object type: Route \n Object name: N/A \n Issue: Management routes are not supported by Alteon! \n line: ' + net + ' ' + gw + '\n')
            # route_list.append(net+' '+gw)

        try:
            c = 0
            mng_dict.update({'ntp': {}})
            for line in re.search(r'sys ntp.+\n( .+\n)+}', text).group(0).splitlines():
                if "servers" in line:
                    line = line.replace('  ', '').replace('servers {', '').replace('}', '')
                    for srv in line.split(' '):
                        if srv != '':
                            c += 1
                            if c == 1:
                                mng_dict['ntp'].update({'prisrv': srv})
                            elif c == 2:
                                mng_dict['ntp'].update({'secsrv': srv})
                elif "timezone" == line.replace('  ', '')[0:8]:
                    ntp_tz = line.replace('  ', '').replace('timezone ', '')
                    if ntp_tz in timezone_dict:
                        mng_dict['ntp'].update({'tzone': timezone_dict[ntp_tz]})
                    else:
                        mng_dict['ntp'].update({'tzone': '0'})
                elif line != "}":
                    log_unhandeled.append(
                        ' Object type: L3 Interface \n Object name: ' + name + '\n Line: ' + line.replace('  ',
                                                                                                          '') + '\n')

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            pass
            # print("Encountered an error while parsing NTP, error on line %d" % exc_tb.tb_lineno)

        try:
            tmp_dict = {}
            for line in re.sub(r'( +)}\n( )+}\n}', r'\1}',
                               re.search(r'(sys syslog.+\n( .+\n)+})', text).group(0).replace('sys syslog {',
                                                                                              '').replace(
                                   'remote-servers {', '')).replace('  ', '').splitlines():
                if '}' in line:
                    tmp += line + '\n'
                else:
                    tmp += ' ' + line
            c = 0
            for line in tmp.splitlines()[:5]:
                c += 1
                line = line.replace('  ', '').replace('}', '')
                name, value = line.split(' { ')
                if '/' in name:
                    junk, rd, name, log_write = fun_rd_split(name.split('/'), "Vlan", log_write)
                    # junk, rd, name = name.split('/')
                else:
                    junk, name = name.split(' ')
                tmp_dict.update({c: {}})
                if not 'remote-port' in value:
                    tmp_dict[c].update({'remote-port': '514'})
                val_list = value.split(' ')
                for x in range(0, len(val_list) - 1):
                    if x % 2 == 0:
                        tmp_dict[c].update({val_list[x]: val_list[x + 1]})
            mng_dict.update({'syslog': tmp_dict})
        except Exception as e:
            pass

        tmp_dict = {}

        try:
            mng_dict.update({'ssnmp': {}})
            snmp = re.search(r'(sys snmp.+\n( .+\n)+})', text).group(0)
            try:
                try:
                    for comm in snmp[snmp.index('communities') + 14:snmp.index('\n    }\n',
                                                                               snmp.index('communities'))].replace('  ',
                                                                                                                   '').replace(
                        '\n', '##=##').split('}'):
                        if comm[0:5] == '##=##':
                            comm = comm[5:]
                        if '{' in comm:
                            junk, rd, comm = comm.split('/')
                            comm_id, comm_atrib = comm.split('{')

                        comm_access = 'r'
                        for tmp_atrib in list(filter(None, comm_atrib.split('##=##'))):
                            key, val = tmp_atrib.split(' ')
                            if key == 'community-name':
                                comm_name = val
                            elif key == 'access':
                                comm_access = val
                            else:
                                log_unhandeled.append('Object type: SNMP Config \n Object name: ' + comm_id + '\n Line :' + tmp_atrib)

                        if comm_access == 'r':
                            mng_dict['ssnmp'].update({'rcomm': comm_name})
                        else:
                            mng_dict['ssnmp'].update({'wcomm': comm_name})
                except Exception as e:
                    pass
                try:
                    c = 0
                    for traps in list(filter(None, snmp[snmp.index('traps') + 8:snmp.index('\n    }\n', snmp.index(
                            'traps'))].replace('  ', '').replace('\n', '##=##').split('}'))):
                        c += 1
                        if traps[0:5] == '##=##':
                            traps = traps[:5]
                        if c > 2:
                            log_write.append(
                                ' Object type: SNMP Trap \n Object name: %s \n Issue: Only 2 SNMP trap destinations are supported!\n' % traps)
                        else:
                            if '{' in traps:
                                rd, traps = list(filter(None, traps.split('/')))
                                traps_id, traps_atrib = traps.split('{')

                            for tmp_atrib in list(filter(None, traps_atrib.split('##=##'))):
                                key, val = tmp_atrib.split(' ')
                                if key == 'host':
                                    trap_host = val
                                elif key == 'port':
                                    if not val == '162':
                                        log_write.append(
                                            ' Object type: SNMP Trap \n Object name: %s \n Issue: SNMP traps supported only on port 162! was configured %s\n' % (
                                                traps_id, val))
                            mng_dict['ssnmp'].update({'trap' + str(c): trap_host})
                except Exception as e:
                    pass
            except Exception as e:
                pass
        except Exception as e:
            pass

        tmp_list = []
        try:
            glob_settings = text[text.index('sys global-settings {'):text.index('\n}\n', text.index('sys global-settings {'))]

            index = 0
            while index < len(glob_settings):
                try:
                    index = glob_settings.index('"', index + 1)
                    tmp_list.append(index)
                except Exception as e:
                    break

            for x in fun_loop_mult_val(tmp_list):
                x = x.split('##=##')
            # print(glob_settings.replace(glob_settings[int(x[0]):int(x[1])], glob_settings[int(x[0]):int(x[1])].replace('\n', '\\n')))

            for line in glob_settings.splitlines()[1:-1]:
                # print(line)
                if "hostname" in line:
                    mng_dict['ssnmp'].update({'name': list(filter(None, line.split(' ')))[1]})
                else:
                    log_unhandeled.append(' Object type: global-settings \n Object name: N/A \n Line: %s\n' % line)

        except Exception as e:
            pass
        return log_write, log_unhandeled

    #################
    #               #
    #   Redundancy  #
    #               #
    #################

    def ha_parser(text):
        # tmp = ''
        sync_id=0
        log_write = []
        log_unhandeled = []
        for device in re.findall('(^cm device (.+) {\n(  .+\n)+^})', text, re.MULTILINE):
            if not 'addr' in mng_dict['mmgmt']:
                pass
            elif not 'name' in mng_dict['ssnmp'] and mng_dict['mmgmt']['addr'] in device[0]:
                dev_name=re.search(r'cm device (/.+/)?(.+) {', device[0]).group(2)
                mng_dict['ssnmp'].update(dict(name='"'+dev_name+'"'))
            elif 'name' in mng_dict['ssnmp'] and mng_dict['ssnmp']['name']==re.search(r'cm device (/.+/)?(.+) {', device[0]).group(2):
                continue
            else:
                sync_list.append(re.search(r'configsync-ip (.+)', device[0]).group(1))
                sync_peer=re.search(r'configsync-ip (.+)', device[0])
                if sync_peer:
                    sync_peer=sync_peer.group(1)

                ha_dict['peer'].append( sync_peer )
                mirror_ip = re.search(r'mirror-ip (.+)', device[0])
                if mirror_ip:
                    mirror_ip=mirror_ip.group(1)

                unicast_ip = re.search(r'( )+ip (.+)', device[0])
                if unicast_ip:
                    unicast_ip=unicast_ip.group(2)

                
                for self in ifDict:
                    tmp_ip=ifDict[self]['addr']+'/'+ifDict[self]['mask']
                    if mirror_ip and ipaddress.ip_address(mirror_ip) in ipaddress.ip_network(tmp_ip, False):
                        ifDict[self]['peer']=mirror_ip
                        if 'def' in ha_dict:
                            ha_dict['def'].append( str(ifDict[self]['if_id']) )
                            ha_dict['def'] = list(set(ha_dict['def']))
                        else:
                            ha_dict.update({'def': [str(ifDict[self]['if_id'])]})
                    if unicast_ip and ipaddress.ip_address(unicast_ip)in ipaddress.ip_network(tmp_ip, False):
                        ifDict[self]['peer']=unicast_ip
                        if 'def' in ha_dict:
                            ha_dict['def'].append( str(ifDict[self]['if_id']) )
                            ha_dict['def'] = list(set(ha_dict['def']))
                        else:
                            ha_dict.update({'def': [str(ifDict[self]['if_id'])]})
                    # print(ipaddress.ip_address(sync_peer) in ipaddress.ip_network(tmp_ip))
        return log_write, log_unhandeled

    #################
    #               #
    #   Ltm Policy  #
    #               #
    #################


    def ltm_policy_parser(text):
        if len(cntrule_dict.keys()) != 0 or len(cntclss_dict.keys()) != 0:
            return [], []
        log_write = []
        log_unhandeled = []
        # ltmpol_dict
        for ltmpol in re.findall(r'(^ltm policy (.+) {\n(  .+\n)+^})', text, re.MULTILINE):
            str_ltmpol = ''.join(ltmpol)
            str_ltmpol = str_ltmpol[:str_ltmpol.rindex('}')+1]
            name=str_ltmpol.splitlines()[0].split()[2]
            if "/" in name:
                name="".join(name.split('/')[-1:])
            cntrule_dict.update({name:{}})
            cntclss_dict.update({name:{}})
            rules=re.search(r'(    rules (.+\n)*?    })', str_ltmpol, re.MULTILINE)
            if rules != None:
                str_ltmpol=str_ltmpol.replace(rules.group(0), '')
                for rule in re.findall(r'(        (.+) {\n(.+\n)*? {8}})', rules.group(0), re.MULTILINE):
                    str_rule = ''.join(rule)
                    r_name = str_rule.splitlines()[0].split()[0]
                    cntrule_dict[name].update({r_name:{}})

                    actions=re.search(r'( {12}actions {\n((.+\n)*?) {12})}', str_rule, re.MULTILINE)
                    if actions != None:
                        str_rule = str_rule.replace(actions.group(0), '')
                        for action in re.findall(r' {16}([\d]+) {\n((.+\n)*?) {16}}', actions.group(1), re.MULTILINE):
                            aid=str(int(action[0])+1)
                            cntrule_dict[name][r_name].update({aid:{}})
                            tmp=action[1].replace('  ','').splitlines()
                            if tmp[0] == "forward":
                                if tmp[1] == "select":
                                    if tmp[2][0:4] == "pool":
                                        if "/" in tmp[2][5:]:
                                            cntrule_dict[name][r_name][aid].update({'group': "".join(tmp[2][5:].split('/')[-1:])})
                                        else:
                                            cntrule_dict[name][r_name][aid].update({'group': tmp[2][5:]})
                                    else:
                                        log_unhandeled.append(' Object type: LTM Policy Action \n Object name: %s \n Line: %s\n' % (name, tmp[2]))
                                else:
                                    log_unhandeled.append(' Object type: LTM Policy Action \n Object name: %s \n Line: %s\n' % (name, tmp[1]))
                            elif tmp[0] == "http-reply":
                                if tmp[1] == "redirect":
                                    cntrule_dict[name][r_name][aid].update({'action': tmp[1]})
                                    if tmp[2][0:8] == "location":
                                        cntrule_dict[name][r_name][aid].update({'redirect': '"'+tmp[2][9:]+'"'})
                                    else:
                                        log_unhandeled.append(' Object type: LTM Policy Action \n Object name: %s \n Line: %s\n' % (name, tmp[2]))
                                else:
                                    log_unhandeled.append(' Object type: LTM Policy Action \n Object name: %s \n Line: %s\n' % (name, tmp[1]))
                            else:
                                log_unhandeled.append(' Object type: LTM Policy Action \n Object name: %s \n Line: %s\n' % (name, action[1]))

                    conditions=re.search(r'( {12}conditions {\n((.+\n)*?) {12})}', str_rule, re.MULTILINE)
                    if conditions != None:
                        str_rule = str_rule.replace(conditions.group(0), '')
                        for condition in re.findall(r' {16}([\d]+) {\n((.+\n)*?) {16}}', conditions.group(1), re.MULTILINE):
                            flag=''
                            aid=str(int(condition[0])+1)
                            tmp=condition[1].replace('  ','').splitlines()
                            if "http" in tmp[0]:
                                cntclss_dict[name][r_name]='http'
                                if tmp[1] == 'host':
                                    tmp.remove('host')
                                    flag='host'
                                if tmp[1] == "ends-with":
                                    match= 'sufx'
                                elif tmp[1] == 'contains':
                                    pass
                                elif tmp[1] == 'starts-with':
                                    match='prefx'
                                elif tmp[1][0:7] == "values ":
                                    match='equal'
                                else:
                                    log_unhandeled.append(' Object type: LTM Policy Condition \n Object name: %s \n Line: %s\n' % (name, tmp[1]))
                                
                                value=tmp[len(tmp)-1].replace('values {', '').replace('}', '').split()
                            if tmp[0] == 'http-host':
                                if len(value)==1:
                                    cntclss_dict[name].update({r_name+" http/hostname "+aid: {'hostname': '"'+value[0]+'"'}})
                                else:
                                    dataclss_dict.update({r_name+"_"+aid:{}})
                                    for key in value:
                                        dataclss_dict[r_name+"_"+aid].update({"data": '"'+key+'" ""'})
                                    cntclss_dict[name].update({r_name+" http/hostname "+aid:{'dataclss': r_name+"_"+aid}})
                                
                                if name in cntrule_dict and r_name in cntrule_dict[name] and aid in cntrule_dict[name][r_name]:
                                    cntrule_dict[name][r_name][aid].update({'cntclss': r_name})
                            elif tmp[0] == 'http-uri':
                                if len(value)==1:
                                    cntclss_dict[name].update({r_name+" http/path "+aid: {'path': '"'+value[0]+'"'}})
                                else:
                                    dataclss_dict.update({r_name+"_"+aid:{}})
                                    for key in value:
                                        dataclss_dict[r_name+"_"+aid].update({"data": '"'+key+'" ""'})
                                    cntclss_dict[name].update({r_name+" http/hostname "+aid:{'dataclss': r_name+"_"+aid}})
                                
                                if name in cntrule_dict and r_name in cntrule_dict[name] and aid in cntrule_dict[name][r_name]:
                                    cntrule_dict[name][r_name][aid].update({'cntclss': r_name})
                            elif tmp[0] == 'http-referer':
                                if len(value)==1:
                                    cntclss_dict[name].update({r_name+" http/header "+aid: {'header': "header NAME=referer \"VALUE="+value[0]+"\"", 'match': 'match NAME=equal "VALUE='+match+'"'}})
                                else:
                                    log_write.append(' Object type: LTM Policy \n Object name: %s \n Issue: Dataclass is not supported for header type content class, please validate rule manually\n' % name)

                                if name in cntrule_dict and r_name in cntrule_dict[name] and aid in cntrule_dict[name][r_name]:
                                    cntrule_dict[name][r_name][aid].update({'cntclss': r_name})
                            elif tmp[0][0:3] == "ssl":
                                log_unhandeled.append(' Object type: LTM Policy SSL Condition \n Object name: %s \n Line: %s\n' % (name, condition[1]))
                                continue
                            else:
                                log_unhandeled.append(' Object type: LTM Policy Condition \n Object name: %s \n Line: %s\n' % (name, condition[1]))
                                continue
                            
                    for line in str_rule.splitlines()[1:]:
                        line=line.replace('  ','')
                        if line[0:1]=="}" or line == '':
                            pass
                        elif line[0:7]=="ordinal":
                            order=line[8:]
                        else:
                            log_unhandeled.append(' Object type: LTM Policy Rule \n Object name: %s \n Line: %s\n' % (name, line))
            for line in str_ltmpol.splitlines()[1:]:
                line=line.replace('  ','')
                if line[0:8] == "controls":
                    controls=line[11:-1].split()
                    if len(controls) > 1:
                        log_write.append(' Object type: LTM Policy \n Object name: %s \n Issue: multiple controls used (%d), please validate rule manually\n' % (name, len(controls)))
                elif line[0:8] == "requires":
                    requires=line[11:-1].split()
                    if len(requires) > 1:
                        log_write.append(' Object type: LTM Policy \n Object name: %s \n Issue: multiple requires used (%d), please validate rule manually\n' % (name, len(requires)))
                elif line[0:8] == "strategy":
                    strategy=line.split()[1]
                    if "/" in strategy:
                        strategy = "".join(strategy.split('/')[-1:])
                    if strategy != "first-match":
                        log_write.append(' Object type: LTM Policy \n Object name: %s \n Issue: Strategy not supported: %s, please validate rule manually\n' % (name, strategy))
                elif line in [' ','', '}']:
                    pass
                else:
                    log_unhandeled.append(' Object type: LTM Policy \n Object name: %s \n Line: %s\n' % (name, line))


        return log_write, log_unhandeled

    #################
    #               #
    #    Routes     #
    #               #
    #################

    def route_parser(text):
        global gw_id

        log_write = []
        log_unhandeled = []

        for route in re.findall('(^net route .+{\n(  .+\n)+^})', text, re.MULTILINE):
            pool=""
            strRoute = ''.join(route[:-1])
            if not '  network ' in strRoute:
                log_write.append(
                    ' Object type: Route \n Object name: N/A \n Issue: Route is not simple L3! please address manually%s\n' % (
                        strRoute))
            for line in strRoute.splitlines():
                line = line.replace('  ', '')
                if 'net route' in line:
                    line = line.replace('net route ', '').replace(' {', '')
                    # print(line)
                    if '/' == line[0]:
                        route_name = list(filter(None, line.split('/')))
                        rd = route_name[0]
                        route_name = '/'.join(route_name[1:])
                    # rd, route_name=list(filter(None, line.split('/')))
                    else:
                        route_name = list(filter(None, line.split(' ')))
                elif line[0:len('gw')] == 'gw':
                    gw = line.split()[1]
                elif line[0:len('network')] == 'network':
                    net = line.split()[1]
                    if net == 'default':
                        net = '0.0.0.0 0.0.0.0'
                    elif '%' in net:
                        log_write.append('Route domain found in route defeniton, please address manually to route %s\n' % (net))
                    else:
                        net, mask = net.split('/')
                        net = net + ' ' + prefixToMaskDict[mask]
                elif line.replace(' ','')[0:4]=="pool":
                    pool=line[line.index('pool')+5:]
                    log_write.append(' Object type: Route \n Object name: N/A \n Issue: using group (%s) as next-hop, please address manually\n' % (pool))
            if pool != "":
                pass
            elif net == '0.0.0.0 0.0.0.0':
                gw_id += 1
                gw_dict.update({gw_id: {'addr': gw, 'ena': ' '}})
            elif '%' in net:
                pass
            else:
                route_list.append('%s %s' % (net, gw))
        return log_write, log_unhandeled

    #################
    #               #
    #    Trunks     #
    #               #
    #################

    def trunk_parser(text):
        global trunk_id
        global lacp_id

        log_write = []
        log_unhandeled = []

        for trunk in re.findall('(^net trunk .+{\n(  .+\n)+^})', text, re.MULTILINE):
            strTrunk = ''.join(trunk[:-1])
            if not "interfaces" in strTrunk:
                continue
            trunk_name = strTrunk.splitlines()[0].replace('net trunk ', '').replace(' {', '')
            strTrunk = '\n'.join(strTrunk.replace('  ', '').splitlines()[1:-1])
            trunk_mem = list(filter(None, strTrunk[strTrunk.index('{') + 1:strTrunk.index('}')].split('\n')))
            for ind, mem in enumerate(trunk_mem):
                if '1.' in mem:
                    trunk_mem[ind] = mem.replace('1.', '')
                elif '.' in mem:
                    trunk_mem[ind] = mem.replace('.', '')
            if 'lacp enabled' in strTrunk:
                lacp_id += 1
                lacp_dict.update({trunk_name: {'lacp_id': lacp_id, 'port': trunk_mem}})
            else:
                trunk_id += 1
                trunk_dict.update({trunk_name: {'trunk_id': trunk_id, 'members': trunk_mem, 'name': trunk_name}})
        return log_write, log_unhandeled

    #################
    #               #
    #    filters    #
    #               #
    #################

    def filter_parser(l):
        global filt_id

        log_write = []
        log_unhandeled = []

        for virt in l:
            filt_id += 50
            filter_dict.update({filt_id: {}})
            l.remove(virt)
            try:
                vlans = re.search(r'    vlans {\n( .+\n)    }\n.+\n', virt)
                if vlans == None:
                    vlan = 'any'
                else:
                    vlans=vlans.group(0)
                    virt = virt.replace(vlans, '')
                    if not vlans.splitlines()[-1].replace('  ', '') == 'vlans-enabled':
                        log_write.append("Error while parsing Virt\n"+virt)
                    vlans = vlans.splitlines()[1:-2]
                    if len(vlans) > 1:
                        vlan = 'any'
                    elif vlans[0].replace(' ', '') in vlanDict:
                        vlan = vlanDict[vlans[0].replace(' ', '')]['tag']
                    else:
                        vlan = vlans[0].replace(' ', '')
                    filter_dict[filt_id].update({'vlan': vlan})
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print("Encountered an error while looking for VLAN in convertion of virt to filter, error on line %d" % exc_tb.tb_lineno)
            
            try:
                irules = re.search(r'    rules {\n( .+\n)    }\n', virt)
                if irules != None:
                    irules=irules.group(0)
                    virt = virt.replace(irules, '')
                    irules = irules.replace('    ', '').replace('rules {', '').replace('}', '')
                    log_write.append("Virt \"%s\" uses the following iRules \"%s\", please convert manually " % (*virt.replace('{', '').splitlines()[0].split()[-1:], ','.join(list(filter(None, irules.splitlines())))))
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print("Encountered an error while looking for iRules in convertion of virt to filter, error on line %d" % exc_tb.tb_lineno)

            try:
                if " profiles " in virt:
                    profiles = re.search(r'    profiles {\n( .+\n)*?    }\n', virt).group(0)
                    virt = virt.replace(profiles, '')
                    profiles = profiles.replace(' ', '').replace('profiles', '').replace('}', '').replace('{', '')
            # print(list(filter(None, profiles.splitlines())))
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print("Encountered an error while looking for profiles in convertion of virt to filter, error on line %d, error=%s" % (exc_tb.tb_lineno, e))

            try:
                str_snat = re.search(r'(    source-address-translation {\n([^}]+\n)+    })', virt).group(0)
                if str_snat != None:
                    for line in str_snat.replace('  ', '').splitlines()[1:-1]:
                        x, y = line.split()
                        if x == 'type':
                            if y == 'automap' or y == 'auto':
                                log_write.append("Found use of Snat Auto, please address manually!\n"+virt)
                        else:
                            log_unhandeled.append(' Object type: Address translation\n Object name: N/A \nLine: ' + x + "," + y)
                    virt = virt.replace(str_snat, '')
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print("Encountered an error while looking for profiles in convertion of virt to filter, error on line %d, error=%s" % (exc_tb.tb_lineno, e))

            for line in virt.replace('    ', '').splitlines():
                if line[0:12] == 'ltm virtual ':
                    line = line.replace('ltm virtual ', '')
                    if '/' in line:
                        linesplit=list(filter(None, line.split('/')))
                        lenlinesplit=len(linesplit)
                        rd=linesplit[0]
                        name = linesplit[lenlinesplit-1]
                        if lenlinesplit>1:
                            log_write.append("found iAPP used in VIRT name: %s!" % line)
                    else:
                        name = line.split()[0]
                    filter_dict[filt_id].update({'name': '"' + name.replace('{', '').replace(' ', '') + '"'})
                elif line[0:11] == 'destination':
                    dip, dport = line[12:].split(':')
                    if "/" in dip:
                        junk, tmp_rd, dip = dip.split('/')
                        if rd != tmp_rd:
                            log_write.append("Please verify object %s, inconsistancy in route domain configuration!" % name)
                    if "%" in dip:
                        log_write.append("Please verify object %s, route domain in destination ip will be ignored. make sure logic remained!" % name)
                        dip = dip.split('%')[0]
                    if dip[0] == '/':
                        dip = '/'.join(list(filter(None, dip.split('/')))[1:])
                    if dip == 'any':
                        dip = '0.0.0.0'
                    filter_dict[filt_id].update({'dip': dip, 'dport': dport})
                elif line[0:4] == 'mask':
                    dmask = line[5:]
                    if dmask == 'any':
                        dmask = '0.0.0.0'
                    filter_dict[filt_id].update({'dmask': dmask})
                elif line[0:26] == 'source-address-translation':
                    # print(line)
                    sip, smask = line[7:].split('/')
                    filter_dict[filt_id].update({'sip': sip, 'smask': prefixToMaskDict[smask]})
                elif line[0:6] == 'source':
                    sip, smask = line[7:].split('/')
                    filter_dict[filt_id].update({'sip': sip, 'smask': prefixToMaskDict[smask]})
                elif line[0:17] == 'translate-address':
                    nat = line.split(' ')[1]
                    if nat == 'disabled':
                        continue
                    else:
                        # print('Address translation enabled')
                        pass
                elif line[0:14] == 'translate-port':
                    nat = line.split(' ')[1]
                    if nat == 'disabled':
                        continue
                    else:
                        # print('Port translation enabled')
                        pass
                elif line.split(' ')[0] in ['vs-index', '}']:
                    continue
                elif line == 'ip-forward':
                    filter_dict[filt_id].update({'action': 'allow'})
                elif line[0:4] == 'pool':
                    filter_dict[filt_id].update({'action': 'redir', 'group': line.split()[1]})
                else:
                    pass
        return l, log_write , log_unhandeled

    def snat_parser(l):
        log_write = []
        log_unhandeled = []
        
        snatp_list = []

        stop=0
        while not stop:
            try:
                snatt = re.search(r'ltm snat-translation (.+) {\n( .+\n)+}\n', l).group(0)
                l=l.replace(snatt, "")
                
                for line in snatt.splitlines():
                    if 'ltm snat-translation' in line: 
                        junk, rd, name = line.split('/')
                        name = name.replace(' {','')
                        snatt_dict.update({name: {}})
                    elif '  address' in line:
                        snatt_dict[name].update({'address': line[line.index('  address')+10:]})
                    elif line != '}':
                        log_unhandeled.append(' Object type: Address translation\n Object name: ' + name + '\nLine: ' + line.replace(' ', ''))
            except Exception as e:
                stop=1

        stop=0
        while not stop:
            try:
                snatp = re.search(r'ltm snatpool (.+) {\n( .+\n)+}\n', l).group(0)
                l=l.replace(snatp, "")
                
                snatp_list.append(snatp)
            except Exception as e:
                stop=1            

        for pool in snatp_list:
            if "/" in pool.splitlines()[0]:
                junk, rd, name = pool.splitlines()[0].split('/')
            else:
                rd='Common'
                name = pool.splitlines()[0].split()[2]
            name = name.replace(' {','')
            snatp_dict.update ({name: []})

            try:
                members = re.search(r'    members {\n( .+\n)+    }\n', pool).group(0)
                for line in members.splitlines()[1:-1]:
                    if "/" in line:
                        junk, rd, snat_address = line.split('/')
                    else:
                        snat_address = line.split()[0]
                    snatp_dict[name].append(snat_address)
            except Exception as e:
                raise e

        return log_write, log_unhandeled




    #####################
    #                    #
    #    End of Parsers     #
    #                    #
    #####################
    print("Working on project %s " % project_name)
    log1str = log1banner
    log2str = log2banner
    if mode == 1:
        log1 = open(os.path.join('app/', project_name + '_log1.txt'), 'w+')
        log2 = open(os.path.join('app/', project_name + '_log2.txt'), 'w+')
        out = open(os.path.join('app/', project_name + '_output.txt'), 'w+')
    else:
        log1 = open(project_name + '_log1.txt', 'w+')
        log2 = open(project_name + '_log2.txt', 'w+')
        out = open(project_name + '_output.txt', 'w+')
        tempfile = open(project_name + '_tmp.txt', 'w+')
    log1.write(log1banner)
    log2.write(log2banner)
    fun_create_empty_dicts()
    return_string: str = ''
    for file in list(filter(None, filename.split('$val$'))):
        print("Now Parsing %s" % file)
        f = open(file, 'r')
        fun_parsers_runner(f.read())
        print("Finished with %s" % file)
        f.close()

    for x in nodeDict:
        return_string += ("\n/c/slb/real %s\n    ena\n" % x)
        out.write("\n/c/slb/real %s\n    ena\n" % x)
        for y in nodeDict[x]:
            if y == 'weight' and nodeDict[x][y]==1:
                continue
            return_string += ("    %s %s\n" % (y, nodeDict[x][y]))
            out.write("    %s %s\n" % (y, nodeDict[x][y]))
    # print("/c/slb/real %s\n    ena\n    rip %s\n" % (x, nodeDict[x]))

    for x in poolDict:
        return_string += ("\n/c/slb/group %s\n    ipver v4\n    health %s\n    metric %s\n" % (
            x, poolDict[x]['advhc'], poolDict[x]['metric']))
        out.write("\n/c/slb/group %s\n    ipver v4\n    health %s\n    metric %s\n" % (
            x, poolDict[x]['advhc'], poolDict[x]['metric']))
        if 'backup' in poolDict[x]:
            return_string += ('    backup %s\n' % poolDict[x]['backup'])
            out.write('    backup %s\n' % poolDict[x]['backup'])
        if 'name' in poolDict[x]:
            return_string += ('    name %s\n' % poolDict[x]['name'])
            out.write('    name %s\n' % poolDict[x]['name'])
        # print("/c/slb/group %s\n    ipver v4\n    health %s\n" % (x, poolDict[x]['advhc']))
        for y in poolDict[x]['members']:
            # print("    add %s" % y.split(':')[0])
            return_string += ("    add %s\n" % y.split(':')[0])
            out.write("    add %s\n" % y.split(':')[0])

    # print(monitorDict)
    for x in monitorDict:
        # print('\n/c/slb/advhc/%s %s\n    ena\n    inter %s\n    timeout %s\n    retry %s' % (x, monitorDict[x]['type'].upper(), monitorDict[x]['inter'], monitorDict[x]['timeout'], monitorDict[x]['retry']))
        if not 'hcType' in monitorDict[x]:
            continue
        return_string += ('\n/c/slb/advhc/health %s %s\n' % (x, monitorDict[x]['hcType'].upper()))
        out.write('\n/c/slb/advhc/health %s %s\n' % (x, monitorDict[x]['hcType'].upper()))
        # return_string+=('\n/c/slb/advhc/%s %s\n    ena\n' % (x, monitorDict[x]['hcType'].upper())
        # out.write ('\n/c/slb/advhc/%s %s\n    ena\n' % (x, monitorDict[x]['hcType'].upper())
        for y in monitorDict[x]:
            if not y in ['hcType', 'advtype']:
                # print('    %s %s' % (y, monitorDict[x][y] ))
                return_string += ('    %s %s\n' % (y, monitorDict[x][y]))
                out.write('    %s %s\n' % (y, monitorDict[x][y]))
        if monitorDict[x]['advtype'] != {}:
            if 'http' in monitorDict[x]['hcType']:
                # print('    http')
                return_string += '    http\n'
                out.write('    http\n')
            else:
                # print('    %s' % monitorDict[x]['hcType'],)
                if monitorDict[x]['hcType'] == 'logexp':
                    return_string += ('    %s %s\n' % (monitorDict[x]['hcType'], monitorDict[x]['advtype']['expr']))
                    out.write('    %s %s\n' % (monitorDict[x]['hcType'], monitorDict[x]['advtype']['expr']))
                    continue
                else:
                    return_string += ('    %s\n' % monitorDict[x]['hcType'])
                    out.write('    %s\n' % monitorDict[x]['hcType'])
            for y in monitorDict[x]['advtype']:
                # print('        %s %s' % (y, monitorDict[x]['advtype'][y]),)
                return_string += ('        %s %s\n' % (y, monitorDict[x]['advtype'][y]))
                out.write('        %s %s\n' % (y, monitorDict[x]['advtype'][y]))

    for x in snatp_dict:
        return_string += ('/c/slb/nwclss %s\n    type \"address\"\n    ipver v4\n' % x)
        out.write('/c/slb/nwclss %s\n    type \"address\"\n    ipver v4\n' % x)
        c=1
        for y in snatp_dict[x]:
            return_string += ('/c/slb/nwclss %s/network %d\n    net subnet %s 255.255.255.255 include\n' % (x, c, y))
            out.write('/c/slb/nwclss %s/network %d\n    net subnet %s 255.255.255.255 include\n' % (x, c, y))
            c+=1


    for x in virt_dict:
        # print('/c/slb/virt %s\n    ena\n    ipver v4\n    vip %s' % (x,virtDict[x]['vip']))
        if virt_dict[x]['vip'] == '0.0.0.0':
            continue
        return_string += ('/c/slb/virt %s\n    ena\n    ipver v4\n    vip %s\n' % (x, virt_dict[x]['vip']))
        out.write('/c/slb/virt %s\n    ena\n    ipver v4\n    vip %s\n' % (x, virt_dict[x]['vip']))
        if 'disable' in virt_dict[x]:
            return_string += ('    disable\n')
            out.write('    disable\n')
        if 'name' in virt_dict[x]:
            # print('    vname '+virtDict[x]['name'])
            return_string += ('    vname %s\n' % virt_dict[x]['name'])
            out.write('    vname %s\n' % virt_dict[x]['name'])
        # print('/c/slb/virt %s/service %s %s' % (x, virtDict[x]['dport'], virtDict[x]['aplic']))
        return_string += ('/c/slb/virt %s/service %s %s\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
        out.write('/c/slb/virt %s/service %s %s\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
        for y in virt_dict[x]['service']:
            return_string += ('    %s %s\n' % (y, virt_dict[x]['service'][y]))
            out.write('    %s %s\n' % (y, virt_dict[x]['service'][y]))
        if 'pip' in virt_dict[x]:
            return_string += ('/c/slb/virt %s/service %s %s/pip\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
            out.write('/c/slb/virt %s/service %s %s/pip\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
            for z in virt_dict[x]['pip']:
                return_string += ('    %s %s\n' % (z, virt_dict[x]['pip'][z]))
                out.write('    %s %s\n' % (z, virt_dict[x]['pip'][z]))
        if "cntclss" in virt_dict[x]:
            for y in virt_dict[x]['cntclss']:
                return_string += ('/c/slb/virt %s/service %s %s/%s\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic'],y))
                out.write('/c/slb/virt %s/service %s %s/%s\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic'],y))
                for z in virt_dict[x]['cntclss'][y]:
                    return_string += ('    %s %s\n' % (z, virt_dict[x]['cntclss'][y][z]))
                    out.write('    %s %s\n' % (z, virt_dict[x]['cntclss'][y][z]))
                return_string += ('/c/slb/virt %s/service %s %s\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
                out.write('/c/slb/virt %s/service %s %s\n' % (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))


        if 'persist' in virt_dict[x]:
            # print(virtDict[x]['persist'])
            if virt_dict[x]['persist']['type'] == 'cookie':
                if 'method' in virt_dict[x]['persist']:
                    cMethod = virt_dict[x]['persist']['method']
                else:
                    cMethod = 'insert'
                if 'cookie-name' in virt_dict[x]['persist']:
                    cName = '"' + virt_dict[x]['persist']['cookie-name'] + '"'
                else:
                    cName = '"MyPersistCookie"'
                if 'expiration' in virt_dict[x]['persist']:
                    c_expir=virt_dict[x]['persist']['expiration']
                else:
                    c_expir=600
                if "cookie-AS" in virt_dict[x]['persist']:
                    # print(virt_dict[x]['persist'])
                    return_string+=("/c/slb/appshape/script %s/ena/import text\nwhen HTTP_REQUEST  {\n\tpersist cookie %s %s expires %d relative\n}\n" % (x+"_cookie", cMethod, cName, c_expir))
                    out.write("/c/slb/virt %s/service %s %s/appshape/add 5 %s\n" % (x, virt_dict[x]['dport'], virt_dict[x]['aplic'],x+"_cookie" ))
                    return_string+=(
                            "/c/slb/appshape/script %s/ena/import text\nwhen HTTP_REQUEST  {\n\tpersist cookie %s %s expires %d relative\n}\n" % (
                        x + "_cookie", cMethod, cName, c_expir))
                    out.write("/c/slb/virt %s/service %s %s/appshape/add 5 %s\n" % (
                        x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x + "_cookie"))
                else:
                    # print('pbind %s %s %s 10 10' % (virtDict[x]['persist']['type'], cMethod, cName))
                    return_string += ('    pbind %s %s %s 10 10\n' % (virt_dict[x]['persist']['type'], cMethod, cName))
                    out.write('    pbind %s %s %s 10 10\n' % (virt_dict[x]['persist']['type'], cMethod, cName))
            elif virt_dict[x]['persist']['type'] == 'clientip':
                if 'timeout' in virt_dict[x]['persist']:
                    timeout = virt_dict[x]['persist']['timeout']
                else:
                    timeout = '10'
                return_string += ('    pbind %s\n    ptmout %s\n' % (virt_dict[x]['persist']['type'], timeout))
                out.write('    pbind %s\n    ptmout %s\n' % (virt_dict[x]['persist']['type'], timeout))
            elif virt_dict[x]['persist']['type'] == 'ssl':
                if 'timeout' in virt_dict[x]['persist']:
                    timeout = virt_dict[x]['persist']['timeout']
                else:
                    timeout = '10'
                return_string += ('    pbind %s\n    ptmout %s\n' % (virt_dict[x]['persist']['type'], timeout))
                out.write('    pbind %s\n    ptmout %s\n' % (virt_dict[x]['persist']['type'], timeout))
            else:
                log1str += (' Object type: Virt \n Object name: %s \n Line: %s' % (x, virt_dict[x]['persist']))
                log1.write('\n Object type: Virt \n Object name: %s \n Line: %s\n' % (x, virt_dict[x]['persist']))
        for y in virt_dict[x]['profiles']:
            tmpType = virt_dict[x]['profiles'][y]['type']
            if tmpType == 'one-connect' and virt_dict[x]['aplic'] in ['http', 'https']:
                return_string += ('/c/slb/virt %s/service %s %s/http\n    connmgt ena 10\n'% (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
                out.write('/c/slb/virt %s/service %s %s/http\n    connmgt ena 10\n'% (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
            elif tmpType == 'one-connect':
                return_string += ('/c/slb/virt %s/service %s %s/connmgt ena 10\n'% (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
                out.write('/c/slb/virt %s/service %s %s/connmgt ena 10\n'% (x, virt_dict[x]['dport'], virt_dict[x]['aplic']))
        for z in virt_dict[x]['adv']:
            # print (z)
            return_string += ('/c/slb/virt %s/service %s %s%s %s\n' % (
                x, virt_dict[x]['dport'], virt_dict[x]['aplic'], z, virt_dict[x]['adv'][z]))
            out.write('/c/slb/virt %s/service %s %s%s %s\n' % (
                x, virt_dict[x]['dport'], virt_dict[x]['aplic'], z, virt_dict[x]['adv'][z]))
        # print('/c/slb/virt %s/service %s %s/%s %s\n' % (x, virtDict[x]['dport'], virtDict[x]['aplic'], z, virtDict[x]['adv'][z]))
        if 'ssl' in virt_dict[x]:
            if 'be' in virt_dict[x]['ssl'] and 'fe' in virt_dict[x]['ssl']:
                return_string += (
                        '/c/slb/ssl/sslpol %s/fessl e/convert d/backend/ssl e\n/c/slb/virt %s/service %s %s/ssl/sslpol %s\n' % (
                    x[:32], x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x[:32]))
                out.write('/c/slb/ssl/sslpol %s/fessl e/convert d/backend/ssl e\n/c/slb/virt %s/service %s %s/ssl/sslpol %s\n' % (
                    x[:32], x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x[:32]))
            elif 'fe' in virt_dict[x]['ssl']:
                return_string += (
                        '/c/slb/ssl/sslpol %s/fessl e/convert d/backend/ssl d\n/c/slb/virt %s/service %s %s/ssl/sslpol %s\n' % (
                    x[:32], x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x[:32]))
                out.write('/c/slb/ssl/sslpol %s/fessl e/convert d/backend/ssl d\n/c/slb/virt %s/service %s %s/ssl/sslpol %s\n' % (
                    x[:32], x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x[:32]))
            elif 'be' in virt_dict[x]['ssl']:
                return_string += (
                        '/c/slb/ssl/sslpol %s/fessl d/convert d/backend/ssl e\n/c/slb/virt %s/service %s %s/ssl/sslpol %s\n' % (
                    x[:32], x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x[:32]))
                out.write('/c/slb/ssl/sslpol %s/fessl d/convert d/backend/ssl e\n/c/slb/virt %s/service %s %s/ssl/sslpol %s\n' % (
                    x[:32], x, virt_dict[x]['dport'], virt_dict[x]['aplic'], x[:32]))

    for x in compres_dict:
        # print('/c/slb/accel/compress/comppol %s' % x)
        out.write('/c/slb/accel/compress/comppol %s\n' % x)
        for y in compres_dict[x]:
            if y == 'virt':
                for z in compres_dict[x][y]:
                    virt, service = z.split('##=##')
                    # print( '/c/slb/virt %s/service %s/http/comppol %s' % (virt, service, x))
                    out.write('/c/slb/virt %s/service %s/http/comppol %s\n' % (virt, service, x))
            elif y == 'brwslist':
                c = 0
                for z in compres_dict[x][y]:
                    c += 1
                    # print('/c/slb/accel/compress/brwslist %s/rule %d' % (x, c))
                    out.write('/c/slb/accel/compress/brwslist %s/rule %d\n' % (x, c))
                    if z[0] == '"':
                        # print ('    contentm regex')
                        out.write('    contentm regex\n')
                        z = z.replace('"', '')
                    # print('    content "%s"' % z)
                    out.write('    content "%s\n"' % z)
                # print('/c/slb/accel/compress/comppol %s/brwslist %s' % (x, x))
                out.write('/c/slb/accel/compress/comppol %s/brwslist %s\n' % (x, x))

    for x in vlanDict:
        # print ('/c/l2/vlan %s\n    name %s' % (vlanDict[x]['tag'], x))
        return_string += ('\n/c/l2/vlan %s\n    name %s' % (vlanDict[x]['tag'], x))
        out.write('\n/c/l2/vlan %s\n    name %s' % (vlanDict[x]['tag'], x))
        for y in vlanDict[x]['interfaces']:
            # print('    add %s' % y)
            return_string += ('\n    add %s' % y)
            out.write('\n    add %s' % y)

    for x in ifDict:
        # print ('/c/l3/if %d\n    ena\n    ipver v4\n    address %s\n    mask %s\n    vlan %s\n    name %s' % (ifDict[x]['if_id'], ifDict[x]['address'], ifDict[x]['mask'], ifDict[x]['vlan'], x))
        return_string += (
                '\n/c/l3/if %d\n    ena\n    ipver v4\n    addr %s\n    mask %s\n    vlan %s\n    descr %s\n' % (
            ifDict[x]['if_id'], ifDict[x]['addr'], ifDict[x]['mask'], ifDict[x]['vlan'], x))
        out.write('\n/c/l3/if %d\n    ena\n    ipver v4\n    addr %s\n    mask %s\n    vlan %s\n    descr %s\n' % (
            ifDict[x]['if_id'], ifDict[x]['addr'], ifDict[x]['mask'], ifDict[x]['vlan'], x))
        if 'peer' in ifDict[x]:
            return_string+= '    peer %s\n' % ifDict[x]['peer']
            out.write('    peer %s\n' % ifDict[x]['peer'])

    float_id=0
    for x in floatIfDict:
        float_id+=1
        return_string += (
                '\n/c/l3/ha/floatip %d\n    ena\n    ipver v4\n    addr %s\n    if %s\n' % (
            float_id, floatIfDict[x]['addr'], floatVlanDict[floatIfDict[x]['vlan']]))
        out.write('\n/c/l3/ha/floatip %d\n    ena\n    ipver v4\n    addr %s\n    if %s\n' % (
            float_id, floatIfDict[x]['addr'], floatVlanDict[floatIfDict[x]['vlan']]))
    for x in mng_dict:
        if x[0] == '/':
            # print('/c/sys\n    %s %s' % (x[1:], mng_dict[x]))
            return_string += ('/c/sys\n    %s %s\n' % (x[1:], mng_dict[x]))
            out.write('/c/sys\n    %s %s\n' % (x[1:], mng_dict[x]))
        elif x == 'syslog':
            # print ('/c/sys/'+x)
            return_string += ('/c/sys/%s\n' % x)
            out.write('/c/sys/%s\n' % x)
            for y in mng_dict[x]:
                # print('    hst%d %s 7 7 all %s' % ( y, mng_dict[x][y]['host'], mng_dict[x][y]['remote-port']))
                return_string += ('    hst%d %s 7 7 all %s\n' % (y, mng_dict[x][y]['host'], mng_dict[x][y]['remote-port']))
                out.write('    hst%d %s 7 7 all %s\n' % (y, mng_dict[x][y]['host'], mng_dict[x][y]['remote-port']))
        else:
            # print ('/c/sys/'+x)
            return_string += ('/c/sys/%s\n' % x)
            out.write('/c/sys/%s\n' % x)
            for y in mng_dict[x]:
                # print('    %s %s' % (y, mng_dict[x][y]))
                return_string += ('    %s %s\n' % (y, mng_dict[x][y]))
                out.write('    %s %s\n' % (y, mng_dict[x][y]))

    if route_list:
        # print ('/c/l3/route')
        return_string += '/c/l3/route\n'
        out.write('/c/l3/route\n')
        for x in route_list:
            # print('    add %s' % x)
            return_string += ('    add %s\n' % x)
            out.write('    add %s\n' % x)

    for x in gw_dict:
        # print('/c/l3/gw %d ' % x)
        return_string += ('/c/l3/gw %d\n' % x)
        out.write('/c/l3/gw %d\n' % x)
        for y in gw_dict[x]:
            # print('    %s %s' % (y, gw_dict[x][y]))
            return_string += ('    %s %s\n' % (y, gw_dict[x][y]))
            out.write('    %s %s\n' % (y, gw_dict[x][y]))

    for x in lacp_dict:
        for y in lacp_dict[x]['port']:
            # print('/c/l2/lacp/port %s\n    adminkey %s' % (y, lacp_dict[x]['lacp_id']))
            return_string += ('/c/l2/lacp/port %s\n    adminkey %s\n' % (y, lacp_dict[x]['lacp_id']))
            out.write('/c/l2/lacp/port %s\n    adminkey %s\n' % (y, lacp_dict[x]['lacp_id']))

    for x in trunk_dict:
        # print('/c/l2/trunk %s\n    ena\n    name %s' % (trunk_dict[x]['trunk_id'], trunk_dict[x]['name'] ))
        return_string += ('/c/l2/trunk %s\n    ena\n    name %s\n' % (trunk_dict[x]['trunk_id'], trunk_dict[x]['name']))
        out.write('/c/l2/trunk %s\n    ena\n    name %s\n' % (trunk_dict[x]['trunk_id'], trunk_dict[x]['name']))
        for y in trunk_dict[x]['members']:
            # print('    add %s' % y)
            return_string += ('    add %s\n' % y)
            out.write('    add %s\n' % y)

    for x in filter_dict:
        # print('/c/slb/filt %d' % x)
        return_string += ('/c/slb/filt %d\n    ena\n' % x)
        out.write('/c/slb/filt %d\n    ena\n' % x)
        for y in filter_dict[x]:
            # print('    %s %s' % (y, filter_dict[x][y]))
            return_string += ('    %s %s\n' % (y, filter_dict[x][y]))
            out.write('    %s %s\n' % (y, filter_dict[x][y]))

    for x in cntclss_dict:
        for y in cntclss_dict[x]:
            if type(cntclss_dict[x][y]) == str:
                # print('/c/slb/layer7/slb/cntclss %s %s' % (y,cntclss_dict[x][y]))
                return_string+=('/c/slb/layer7/slb/cntclss %s %s\n' % (y,cntclss_dict[x][y]))
                out.write('/c/slb/layer7/slb/cntclss %s %s\n' % (y,cntclss_dict[x][y]))
            else:
                # print('/c/slb/layer7/slb/cntclss %s' % y)
                return_string+=('/c/slb/layer7/slb/cntclss %s\n' % y)
                out.write('/c/slb/layer7/slb/cntclss %s\n' % y)
                for z in cntclss_dict[x][y]:
                    # print('    %s %s' % (z, cntclss_dict[x][y][z]))
                    return_string+=('    %s %s\n' % (z, cntclss_dict[x][y][z]))
                    out.write('    %s %s\n' % (z, cntclss_dict[x][y][z]))

    c=0
    for y in ha_dict['peer']:
        c+=1
        return_string+='\n/c/slb/sync/peer %d\n    ena\n    addr %s\n\n' % (c, y)
        out.write('\n/c/slb/sync/peer %d\n    ena\n    addr %s\n\n' % (c, y))

    if 'def' in ha_dict and len(ha_dict['def'])>0:
        tmp=" ".join(ha_dict['def'])
        return_string +='/c/l3/hamode switch\n/c/l3/ha/switch\n    def %s' % tmp
        out.write('/c/l3/hamode switch\n/c/l3/ha/switch\n    def %s' % tmp)

    if virt_dict == {} and poolDict == {} and nodeDict == {} and monitorDict == {} and ifDict == {} and floatIfDict == {} and vlanDict == {}:
        print('\n\nDid not find any objects, please make sure using TMSH config')

    log1.close()
    log2.close()
    out.close()

    if mode == 1:
        fin_arch = tarfile.open(os.path.join('app/', project_name) + '.tar', mode='w')
        fin_arch.add(os.path.join('app/', project_name + '_log1.txt'), arcname=project_name + '_log1.txt')
        fin_arch.add(os.path.join('app/', project_name + '_log2.txt'), arcname=project_name + '_log2.txt')
        fin_arch.add(os.path.join('app/', project_name + '_output.txt'), arcname=project_name + '.txt')
        fin_arch.close()
        return ('''
                <html>
                  <head>
                    <title>F5 Migration Tool</title>
                  </head>
                  <body>
                    <div align="center">
                      <h1>Wellcome to F5 Migration!</h1>
                      <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/4QAiRXhpZgAATU0AKgAAAAgAAQESAAMAAAABAAEAAAAAAAD/7AARRHVja3kAAQAEAAAAZAAA/9sAQwACAQECAQECAgICAgICAgMFAwMDAwMGBAQDBQcGBwcHBgcHCAkLCQgICggHBwoNCgoLDAwMDAcJDg8NDA4LDAwM/9sAQwECAgIDAwMGAwMGDAgHCAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM/8AAEQgBaAJ2AwEiAAIRAQMRAf/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/EAB8BAAMBAQEBAQEBAQEAAAAAAAABAgMEBQYHCAkKC//EALURAAIBAgQEAwQHBQQEAAECdwABAgMRBAUhMQYSQVEHYXETIjKBCBRCkaGxwQkjM1LwFWJy0QoWJDThJfEXGBkaJicoKSo1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoKDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uLj5OXm5+jp6vLz9PX29/j5+v/aAAwDAQACEQMRAD8A/fyis3QPEC67daoiquzT7w2oYfxERxs35MxH4VpUANSCONyyoqs3UgcmnUUUAFFFFABTZII5iN6K2OmRnFOooAKKKKACiiigBs0K3ETRyKskbjDKwyGHoRUOm6RaaNCY7O1t7WNjkrDGI1J9cAVYooHzO1gooooEFFFFAFGXwxptxrC6hJp1i+oRjC3LQKZlHHR8Z7Dv2q9RRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQBynwstntJPEySfe/t24fn0ZUYfoRXV1DbWMVpNcSRoFa6kEsp/vMFVM/8AfKqPwqagAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAozRXz/8cPiFc+KfEtxpo3R6fpk7xInKmR1wrM4yQ2GVtpwMA+pNC1BntT+P9BjnMba1pKyK20obyPcD6Yz1rWr5Hrtfg18TpfBGtR2lxJnS7yVVlDZbyDyAy8gL8xBY4OQPUCq5SeY+g6hv9Qt9LtHuLqaG3gj5aSVwiL25J4qr4s8Qx+FPDd5qMu0raxFwpO3e3RVzzjLED8a+a/F3i698bazJfXzgyOAAiE+XEAAMKCTgd/qSaSVxt2PpPTPF+k63c+TZ6pp15Njd5cNykjY9cA5rRr5HIyK9k/Z++J82qP8A2DfyeZJDFutJGyzyAEllZiTkgEbQB0U+gp8olI9UrkPi1+0H4B+AVtYzeOvHHhDwVDqTOlnJr2s2+mrdMmC4jMzqHK7lyBnG4etfOH/BaH/goHqv7Av7LMN54Tk09fHnjG9Ok6NJchZP7OQRs898sTArKYhsVVbKCSaIsrqGRv519e12+8Va/f6tql5dalqmq3Ml5e3l1KZbi8nkYvJLI7ZLu7EszEkkkk18/mmeLCz9lCPNLr2R+1eHPhBW4jwrzHFVvZUbtRsrylbdq7Sik9L63aastz+rz4V/HXwR8dNMmvfBHjLwr4ys7Vgk0+h6tb6hFExzwzQuwB4PB9K6qv5JfAXjrWPhd450bxN4fv5tK17w/exajp17EFZ7W4iYMjgMCpwR0YFSMgggkH+kb/glL+3hJ/wUJ/ZPtvGF9pMmkeINFv30DW0XH2a5vIoYZWnt8EnypEnjbawBRy6fOFEj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W3k3ZHzrjBAP3B/YkjWH9jD4RIiqqr4K0YKoGAB9hh4Fen1h/DLwBY/Cf4beH/C2mNcSab4a0y20q0a4YPM0UESxIXIABbaoyQACc8CtygAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAPyH/wCC7/7cv7Ufwr/4KafAH4G/s7/FDS/h7J8WtKEROp6LYXtmbxruWNZZJJ7S4lRdqgEICOM7c5NO/wCGMv8AgsP/ANHcfAj/AMENp/8AKCvK/wDg4Q+N/hb9mv8A4L6fsa+PvG2qf2H4T8J2Meo6rfm2mufssCahMWfy4UeRseiKT7V9l/8AEUb+wn/0XL/yzPEH/wAg0AYn7CP7M3/BSb4e/tXeE9Y+Pn7RPwl8efCS0N3/AG/oejaTb299ehrOdLby3TSLdhsumt3OJkyqN977jfo1XzP+xN/wWH/Zy/4KLfELVfCvwb+In/CY69ounHVb21/sDU9P8m2EiRGTfdW0SN88iDarFuc4wCR8a/Aj/gpf8WvhH/wcrfEb9mn4t/Ey71r4X+INMmuPh7ZXfhzT9Miiu7mK01G2hW5ihSaZIYft1mrvK/myRDcDIcKAfrFRXyT/AMFzP21PEH/BP/8A4JefE/4l+DtR0/TPGunw2en6BNdCJ9l3d3kFt5kcUqskskUUkswjZWBEJ3AqGrP+D37UnxG/Y2/4IpWvxl/aQ1a28QfE3wz4HufFmvR6nFb+Gnu72USXFlpEirEsdvc/vbWwwIizTAYR3bDAH2NRX46/sjfDf9vb/gsT8HtR+MWrftJa/wDsteBfGGtT6j4E8IWfgux1G7/sVyHtpmu1a0uHiIO1GmGZ1TzgojljLX/2J/8AgqV8f/2IP+Cplx+yX+2LrsfjuPx1d28Pw7+JEGkw6PZ3jPBuigKJBCs6zu0cBZS7w3YaItMjiSMA/Xui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RZWDOFKKg/X3wl4S0rwD4V0zQtC0zT9F0PRbSKw0/T7C3S3tbC3iQJFDFEgCxxoiqqooAUAAAAVoUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAf/9k=" alt="Rad_logo" />
                    </div>
                    <a>To download the results></a>
                    <a href="/f5_tmsh_finish?filename=''' + project_name + '''">Click Here</a>
                    <br>
                    <a>To start overt</a>
                    <a href="/">Click Here</a>
                    <br>
                    <a>Or view here</a>
                    <table border="1" width="100%" height="100%">
                      <tr>
                        <td valign="top">
                          <a>''' + return_string.replace('\n', '<br>') + '''</a>
                        </td>
                        <td valign="top">
                          <a>''' + log1str.replace('\n\n', '\n').replace('\n', '<br>') + '''</a>
                        </td>
                        <td valign="top">
                          <a>''' + log2str.replace('\n\n', '\n').replace('\n', '<br>') + '''</a>
                        </td>
                      </tr>
                    </table>
                  </body>
                </html>''')
