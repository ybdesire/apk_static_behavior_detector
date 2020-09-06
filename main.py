import os,sys,time,datetime,traceback
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis



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





def main():
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
