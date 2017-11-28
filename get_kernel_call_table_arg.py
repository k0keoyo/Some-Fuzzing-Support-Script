
import idaapi
import idc


def load_ssdt() :
    
    file = open('D:\ssdt.md')
    ssdt = {}
    for index in file :

        if not index.startswith('| Nt') :
            continue
               
        #| NtAcceptConnectPort | 0 | 96 | 6 | 6 | wow64
        
        index = index[2 : ]
        function_name = index[ : index.find('|') ].strip()
        print function_name
        index = index[index.find('|') + 1 : ].strip()
        id32 = index[ : index.find('|') ].strip()
        
        index = index[index.find('|') + 1 : ].strip()
        id64 = index[ : index.find('|') ].strip()
        
        index = index[index.find('|') + 1 : ].strip()
        argc32 = index[ : index.find('|') ].strip()
        
        index = index[index.find('|') + 1 : ].strip()
        argc64 = index[ : index.find('|') ].strip()
        
        ssdt[function_name] = (id32,id64,argc32,argc64)
        
    return ssdt
   
    #return {'Allocate' : (1,2,3,4)}
	

file = open('D:\ssdt_log1.txt','w')

def log(data) :
    file.write(data + '\n')
    

ssdt = load_ssdt()

log('| functionName | syscall id32 | syscall id64 | return Type | arguments Type')

try:
    for ssdt_function in ssdt.keys() :

        address = idc.LocByName(ssdt_function)

        if idc.BADADDR == address :
            continue
        
        function = idaapi.get_func(address)

        try:
            code = idaapi.decompile(function)
        except:
            continue
        function_declare = code.__str__()
        function_declare = function_declare[ : function_declare.find('\n')]
        function_type = function_declare[ : function_declare.find(' ')]
        function_arguments = function_declare[ function_declare.find(ssdt_function) + len(ssdt_function) + 1 : function_declare.rfind(')') ]
    
        if function_arguments.count(',') :
            function_arguments = function_arguments.split(',')
        else :
            function_arguments = [function_arguments]
    
        function_arguments_type = []

        for argument_index in function_arguments :
            struct = argument_index.split(' ')
            if struct[0] == '' and len(struct) > 1 and len(struct) < 4:
                struct[0] = struct[1]
                if '*' in struct[-1]:
                    struct[0] = struct[0] + "_PTR"
            elif len(struct) >= 4:
                struct[0] = struct[-3] + " " + struct[-2]
                if '*' in struct[-1]:
                    struct[0] = struct[0] + "_PTR"
            elif struct[0] != '':
                temp = struct[0].split('(')
                struct[0] = temp[-1]
                if '*' in struct[-1]:
                    struct[0] = struct[0] + "_PTR"
            function_arguments_type.append(struct[0])

    
        ssdt_number = (ssdt[ssdt_function][0],  #  32 bit
                       ssdt[ssdt_function][1])  #  64 bit
    
        print hex(int(ssdt_number[0])),hex(int(ssdt_number[1])),function_type,ssdt_function,function_arguments_type
    
        log(ssdt_function + ' | ' + hex(int(ssdt_number[0])) + ' | ' + hex(int(ssdt_number[1])) + ' | return ' + function_type + ' | ' + str(function_arguments_type))
except Exception,e:
    print 'error' + str(e)
    file.close()
    
print "finish...Check file"
file.close()