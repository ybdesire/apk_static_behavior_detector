import os,sys,time,datetime,traceback
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from behaviors import behavior_patterns


class StaticAnalysis(object):
    def __init__(self, apkfile):
        self.apkfile = apkfile
        self.a = None#apk obj
        self.d = None#dex obj
        self.x = None#analysis result obj
        
    def get_androguard_obj(self):
        try:
            self.a = apk.APK(self.apkfile, False, "r", None, 2)
            self.d = dvm.DalvikVMFormat(self.a.get_dex())
            self.x = analysis.Analysis(self.d)
        except Exception as e:
            msg = traceback.format_exc()
            print(msg)


def get_behavior_pattern_items():
    permission_list = []
    api_list = []
    dexstr_list = []
    for d in behavior_patterns:
        behavior_name = d
        ptn_list = behavior_patterns[d]
        #import pdb;pdb.set_trace()
        for dd in ptn_list:
            for x in dd:
                if 'permission_list'== x:
                    permission_list += dd['permission_list']
                if 'api_list'==x:
                    api_list += dd['api_list']
                if 'dexstr_list'==x:
                    dexstr_list += dd['dexstr_list']
    result = {}
    result['permission_list'] = permission_list
    result['api_list'] = api_list
    result['dexstr_list'] = dexstr_list
    return result


def get_apk_exists_pattern_items(apk_file_path, b_ptn_items):
    # as part of result for return
    permission_list_r = []
    api_list_r = []
    dexstr_list_r = []
    # mid var for enhance parse performance
    count_matched_api = 0
    count_matched_dexstr = 0
    # parse apk
    sa = StaticAnalysis(apk_file_path)
    sa.get_androguard_obj()
    # get exists permissions
    permission_list_e = sa.a.get_permissions()
    for p in b_ptn_items['permission_list']:
        if p in permission_list_e:
            permission_list_r.append(p)
    # get exists method and string
    class_list = sa.d.get_classes()
    for class_item in class_list:
        if count_matched_api>=len(b_ptn_items['api_list']) and count_matched_dexstr>=len(b_ptn_items['dexstr_list']):
            break# break if match completed, enhance parse performance

        class_name = class_item.name
        if 'Landroid/support/v4' in class_name:# filter common lib to enhance performance
            continue
        if 'Landroidx/' in class_name:# filter common lib to enhance performance
            continue

        methods = class_item.get_methods()
        for m in methods:
            if count_matched_api>=len(b_ptn_items['api_list']):
                break# break if match completed, enhance parse performance
            # dex string match here
            if len(b_ptn_items['dexstr_list'])>0:# if no dexstr pattern, avoid this to enhance performance
                strings = v.get_strings_by_method(m)
                dexstr_list_r += list( set(b_ptn_items['dexstr_list']) & set(strings)  )
            raw_code_list = [x for x in m.code.code.get_instructions()]
            for line in raw_code_list:
                code_line_smali = line.get_output()
                if ', ' in code_line_smali:
                    api = code_line_smali.split(', ')[1]
                    if api in b_ptn_items['api_list']:
                        api_list_r.append(api)
                        #print(line.get_output())
                        #print('class-name={0}'.format(class_name))
                        #print('method-name={0} {1}'.format(m.name,m.get_descriptor()))
    result = {}
    result['permission_list'] = permission_list_r
    result['api_list'] = api_list_r
    result['dexstr_list'] = dexstr_list_r
    return result

def main():
    b_ptn_items  = get_behavior_pattern_items()
    print(b_ptn_items)
    b_ptn_items_exists = get_apk_exists_pattern_items('app-debug.apk', b_ptn_items)
    print(b_ptn_items_exists)

    


def detect_deprecated():
    sa = StaticAnalysis('app-debug.apk')
    sa.get_androguard_obj()
    permission_list = sa.a.get_permissions()
    for p in permission_list:
        if 'android.permission.READ_PHONE_STATE' in p:
            print(p)
    print(permission_list)
    class_list = sa.d.get_classes()
    print('class num:{0}'.format(len(class_list)))
    for class_item in class_list:
        class_name = class_item.name
        if 'Landroid/support/v4' in class_name:
            continue
        if 'Landroidx/' in class_name:
            continue
        methods = class_item.get_methods()
        for m in methods:
            raw_code_list = [x for x in m.code.code.get_instructions()]
            for line in raw_code_list:
                if 'getLine1Number' in line.get_output():
                    print(line.get_output())
                    print('class-name={0}'.format(class_name))
                    print('method-name={0} {1}'.format(m.name,m.get_descriptor()))



def test_str_ana():
    sa = StaticAnalysis('1720b2f45fbd5c18b6ddd879bd013aeb3eefdd991c0942046f609a5f0ce952a6')
    sa.get_androguard_obj()
    v = sa.x.get_tainted_variables()
    class_list = sa.d.get_classes()
    for c in class_list:
        class_name = c.name
        ms = c.get_methods()
        for m in ms:
            d = v.get_strings_by_method(m)
            if(len(d)>0):
                for k in d:
                    print( 'STRING: {}\n'.format(k.get_info()) )
                    print('class-name={0}'.format(class_name))
                    print('method-name={0} {1}'.format(m.name,m.get_descriptor()))

    

if __name__=='__main__':
    main()
    #detect_deprecated()
