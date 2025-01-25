//------------------------------------------------------------Bypassing Port Check -------------------------------------------------------------------

var connecPtr = Module.findExportByName("libc.so", "connect");
var connect = new NativeFunction(connecPtr, 'int', ['int', 'pointer', 'int']); 
Interceptor.replace(connecPtr, new NativeCallback(function (fd, addr, len) {
    var family = addr.readU16();
    var port = addr.add(2).readU16();
    port = ((port & 0xff) << 8) | (port >> 8);
	if(port == 27042){
		console.warn('\n[*] Bypassing Frida Check by Port')
		var tmp = (((27043 & 0xff) << 8) | (27043 >> 8));    // 27043 Fake Port 
		port = addr.add(2).writeU16(tmp);
	}
	var port = addr.add(2).readU16();
	port = ((port & 0xff) << 8) | (port >> 8);
    console.log(`[+] connect -> ${port}`);
    return connect(fd, addr, len);
}, 'int', ['int', 'pointer', 'int']));

//------------------------------------------------------------Bypassing Frida-Agent in Memory -------------------------------------------------------------
// Search what is used for Open /Proc/self   by search for syscalls for open files 

var do_dlopen = null;
var call_constructor = null;
Process.findModuleByName("linker64").enumerateSymbols().forEach(function(symbol){
    if(symbol.name.indexOf("do_dlopen") >= 0){
        do_dlopen = symbol.address;
    }
    if(symbol.name.indexOf("call_constructor") >= 0){
        call_constructor = symbol.address;
    }
});

//------------------------------------------------------------
var lib_loaded = 0;
Interceptor.attach(do_dlopen,function(){
    var library_path = this.context.x0.readCString();
    if(library_path.indexOf("libantifrida.so") >= 0){
        Interceptor.attach(call_constructor, function(){
            if(lib_loaded == 0){
                lib_loaded = 1;
                var module = Process.findModuleByName("libantifrida.so");
                console.log(`[+] libantifrida is loaded at ${module.base}`);
                hook_svc(module.base);
            }
        })
    }
});

//------------------------------------------------------------
// Note: Grep App from 'ps -A | antifrida' ; copy maps from memory ' cat /proc/PID/maps > /data/local/tmp/maps' pull it then patch frida-agent then push it back in tmp 

function hook_svc(base_addr){
    var buff = "";
    const syscallArray = [{"addr":3868,"name":"openat","sysnum":56},{"addr":4008,"name":"read","sysnum":63},{"addr":4924,"name":"close","sysnum":57},{"addr":4992,"name":"close","sysnum":57},{"addr":5304,"name":"openat","sysnum":56},{"addr":5440,"name":"read","sysnum":63},{"addr":6272,"name":"openat","sysnum":56},{"addr":6416,"name":"read","sysnum":63},{"addr":6832,"name":"close","sysnum":57},{"addr":6856,"name":"openat","sysnum":56},{"addr":6884,"name":"read","sysnum":63},{"addr":6904,"name":"lseek","sysnum":62},{"addr":7036,"name":"read","sysnum":63},{"addr":7200,"name":"lseek","sysnum":62},{"addr":7232,"name":"read","sysnum":63},{"addr":7368,"name":"close","sysnum":57},{"addr":7480,"name":"close","sysnum":57}];
    syscallArray.forEach(function(item) {
        var addr = ptr('0x'+item.addr.toString(16));
        Interceptor.attach(base_addr.add(addr),function(args){
            switch(item.sysnum){
                case 56:
					if(this.context.x1.readCString().indexOf('self/maps') >= 0){
						console.warn(`\n[+] Bypassing By Patch Maps`);
						this.context.x1.writeUtf8String("/data/local/tmp/maps");
					}
					//------------------------------------
					if(this.context.x1.readCString().indexOf('libc.so') >= 0){
                        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
						console.log(`\nBacktrace:  ${backtrace}`);
					}
					console.log(`[+] Openet -> ${this.context.x1.readCString()}`);
                    break;
                case 63:   
					if(this.context.x1.readCString() != '\n'){
						var singlechar = this.context.x1.readCString();
						buff += singlechar;
					}else{
						// console.log(buff); // Print Maps from Memory by add Chars to Buffer
						buff = "";
					}
					// console.log(`[+] Read -> ${this.context.x1.readCString()}`);
                    break;
                case 57:
                    console.log(`[*] close()`);
                    break;
                case 62:
                    console.log(`[*] lseek -> fd: ${this.context.x0}, offset: ${this.context.x1}`);
                    break;
            }
            
        });
    });
}





