---
layout: post
title:  "HackTheBox Walkie Hackie"
date:   2022-03-06
category: Writeup
image: assets\img\blog\walkie_hackie.png
author: Lukas Marckmiller
tags: ctf
---
1.  Download Challenge files
2.  Open files in e.g Universal Radio Hacker
3.  Select "Show data as" and select "Hex"
4.  Each Signal consists of a preamble, a sync word and the payload in hex
    Preamble: *AAAAAAAA*
    Sync Word: *73214693*
    Payload *A2FF84, A1FF14, B2FF24 and B1FF57*
5.  Idea is to fuzz the variable parts around the FF's in the payload
6.  Create a list for the fuzzer
    ```python
#!/bin/python3
    for i in range(0x00,0xff+1):
       print(f'{i:02x}')
```
7.  Use list with e.g ffuf
    `ffuf  -w 00\_ff.lst:W1,00\_ff.lst:W2 -u http://&lt;ip&gt;:&lt;port&gt;/transmit -X POST -H  "Content-Type: application/x-www-form-urlencoded"  -d  'pa=AAAAAAAA&sw=73214693&pl=W1ffW2'  -c  -fw 403`
8.  Filter default output with **-fw 403** (filter word), you can run it without the filter and observe the common response1
9.  You get back all the results that lead to a different response. With the flag in the response content.