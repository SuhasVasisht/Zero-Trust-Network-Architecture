#queries file 
parameter_names = [
    "H-Test-01",
    "H-Test-02",
    "H-Test-03",
    "H-Test-04",
    "H-Test-05",
    "H-Test-06",
    "H-Test-07",
    "H-Test-08",
    "H-Test-09",
    "H-Test-10",
    "H-Test-11",
    "H-Test-12",
    "H-Test-13",
    "H-Test-14",
    "H-Test-15",
]

parameter_desc_maping = {
    "H-Test-01":"Processes Spawning cmd.exe",
    "H-Test-02":"Suspicious Run Locations",
    "H-Test-03":"Execution with AT",
    "H-Test-04":"Powershell Execution",
    "H-Test-05":"Services launching Cmd",
    "H-Test-06":"Remote PowerShell Sessions",
    "H-Test-07":"Common Windows Process Masquerading",
    "H-Test-08":"Batch File Write to System32",
    "H-Test-09":"Webshell-Indicative Process Tree",
    "H-Test-10":"CMSTP",
    "H-Test-11":"Processes with Deleted Binaries",
    "H-Test-12":"",
    "H-Test-13":"",
    "H-Test-14":"",
    "H-Test-15":"",
}

queries = [
    "select pid,name from processes where pid in (select parent from processes where name='cmd.exe');",#H-Test-1
    "select name from processes where (path='*:\RECYCLER' or path='*:\SystemVolumeInformation');",#H-Test-2
    "select name,cmdline from processes where name='at.exe';",#H-Test-3
    "select name,pid from processes where pid in (select parent from processes where name='powershell.exe' or name='powershell') and name <> 'explorer.exe';",#H-Test-4
    "select name,pid from processes where pid in (select parent from processes where name='cmd.exe' or name='cmd') and name = 'services.exe' or name='services';",#H-Test-5
    "select name,pid from processes where pid in (select parent from processes where name='wsmprovhost.exe' or name='wsmprovhost') and name = 'svchost.exe' or name='svchost';",#H-Test-6
    '''select name,pid,path from processes 
    where (name='svchost.exe' and path <> 'C:\Windows\System32\svchost.exe' and state='STILL_ACTIVE') 
    or (name='smss.exe' and path <> 'C:\Windows\System32\smss.exe' and state='STILL_ACTIVE') 
    or (name='wininit.exe' and path <> 'C:\Windows\System32\wininit.exe' and state='STILL_ACTIVE') 
    or (name='taskhost.exe' and path <> 'C:\Windows\System32\taskhost.exe' and state='STILL_ACTIVE') 
    or (name='lasass.exe' and path <> 'C:\Windows\System32\lsass.exe' and state='STILL_ACTIVE') 
    or (name='winlogon.exe' and path <> 'C:\Windows\System32\winlogon.exe' and state='STILL_ACTIVE') 
    or (name='csrss.exe' and path <> 'C:\Windows\System32\csrss.exe' and state='STILL_ACTIVE') 
    or (name='services.exe' and path <> 'C:\Windows\System32\services.exe' and state='STILL_ACTIVE') 
    or (name='lsm.exe' and path <> 'C:\Windows\System32\lsm.exe' and state='STILL_ACTIVE') 
    or (name='explorer.exe' and path <> 'C:\Windows\explorer.exe' and state='STILL_ACTIVE');''',#H-Test-7
    "select filename,type from file where directory='C:\Windows\System32\' and filename like '%.bat';",#H-Test-8
    '''select name,pid from processes where parent in (select pid from processes where name='w3wp.exe' or name='httpd.exe' or 'name=tomcat*.exe' or name='nginx.exe') 
    and (name='cmd.exe' or name='powershell.exe' or name='net.exe' or name='whoami.exe' or name='hostname.exe' or name='systeminfo.exe' or name='ipconfig.exe');''',#H-Test-9
    "select remote_address from process_open_sockets where pid in (select pid from processes where name='CMSTP.exe') and (remote_address not like '10.0.%' or remote_address not like '192.168.0.%' or remote_address not like '172.16.0.%');",#H-Test-10
    "select name, path, pid from processes where on_disk = 0;",#H-Test-11
    "",#H-Test-12
    "",#H-Test-13
    "",#H-Test-14
    "",#H-Test-15
]

columns = [
    ["pid,name"],#H-Test-1
    ["name"],#H-Test-2
    ["name","cmdline"],#H-Test-3
    ["name","pid"],#H-Test-4
    ["name","pid"],#H-Test-5
    ["name","pid"],#H-Test-6
    ["name","pid","path"],#H-Test-7
    ["filename","type"],#H-Test-8
    ["name","pid"],#H-Test-9
    ["remote_address"],#H-Test-10
    ["name", "path", "pid"],#H-Test-11
    [],#Test-12
    [],#Test-13
    [],#Test-14
    [],#Test-15
]
