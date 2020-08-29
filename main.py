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


if __name__=='__main__':
    main()
