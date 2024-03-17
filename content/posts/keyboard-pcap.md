+++
title = 'Network-KeyLogger'
summary = "how to decode the keystrokes from the pcap"
tags = ["CTF", "Network Forensic", "USB", "HID"]
+++

## Network-KeyLogger

Here is a small writeup for the Network-Logger Challenge from Srdnlen ctf.

We are given a **pcap** file. On opening it in wireshark, we will find it is USB captured data.


![image](https://user-images.githubusercontent.com/89577007/196241863-62cd2ca3-3de4-4fbf-93ac-2399856a5fa2.png)

Following the packet *```DESCRIPTOR Response DEVICE```*, we will find basic information like idVendor,idProduct etc. about the connected devices. 

*Operating System uses idVendor & idProduct to determine a driver for the connected device.*

After analyzing few Leftover data, we are confirmed that It is about keyboard capture.


The `URB_INTERRUPT_TRANSFER` structure is utilized by USB client drivers to transmit data. In this context, the pressed keys data is transferred from the keyboard (`source`) to the computer (`host`).

To filter the data, we can use `usb.capdata` to get only leftover data.

![image](https://user-images.githubusercontent.com/89577007/196245183-00a142cd-09d2-4328-a2de-4fac8991e6d8.png)



![image](https://user-images.githubusercontent.com/89577007/196242698-c3a181f0-a300-4cd1-9de3-65c3822558bd.png)

**0x02**:  ```Left Shift Modifier```

**0x20**: ```Right Shift Modifier```

**0x00**: ``` Normal Key Pressed```

So, if we come across `0x02` or `0x20`, we'll use uppercase letters; otherwise, we'll use lowercase letters when decoding the key data.


Let's write a simple python script to extract these traces of data.
#### Code

```py
 import os
 leftover = os.popen("tshark -r keyboard.pcap -Y \"usb.capdata\" -T fields -e \"usb.capdata\"").readlines()


 usb_codes = {
    "04":['a','A'],"05":['b','B'], "06":['c','C'], "07":['d','D'], "08":['e','E'], "09":['f','F'],"0A":['g','G'],"0B":['h','H'], "0C":['i','I'], "0D":['j','J'], "0E":['k','K'], "0F":['l','L'],"10":['m','M'], "11":['n','N'], "12":['o','O'], "13":['p','P'], "14":['q','Q'], "15":['r','R'],"16":['s','S'], "17":['t','T'], "18":['u','U'], "19":['v','V'], "1A":['w','W'], "1B":['x','X'],"1C":['y','Y'], "1D":['z','Z'], "1E":['1','!'], "1F":['2','@'], "20":['3','#'], "21":['4','$'],"22":['5','%'], "23":['6','^'], "24":['7','&'], "25":['8','*'], "26":['9','('], "27":['0',')'],"28":['\n','\n'], "29":['[Esc]','[Esc]'], "2A":['{backspace}','{backspace}'], "2B":['\t','\t'],"2C":[' ',' '], "2D":['-','_'], "2E":['=','+'], "2F":['[','{'], "30":[']','}'], "31":['\',"|'],"32":['#','~'], "33":";:", "34":"'\"", "36":",<",  "37":".>", "38":"/?","39":['[CAPSLOCK]','[CAPSLOCK]'], "3A":['F1'], "3B":['F2'], "3C":['F3'], "3D":['F4'], "3E":['F5'], "3F":['F6'], "41":['F7'], "42":['F8'], "43":['F9'], "44":['F10'], "45":['F11'],"46":['F12'], "4F":[u'→',u'→'], "50":[u'←',u'←'], "51":[u'↓',u'↓'], "52":[u'↑',u'↑']
   }

 for index in range(len(leftover)):
    try:
        if leftover[index][:2].upper() == '20' or leftover[index][:2].upper() == '02':
            print(usb_codes.get(leftover[index][4:6].upper())[1],end='')
        else:
            print(usb_codes.get(leftover[index][4:6].upper())[0],end='')
    except:
        continue
```
 

#### OUTPUT

```text
Hhello! Wwe are srdnlen, a CER{backspace}{backspace}{backspace}TFteam←←←← →→→→ made up in 2019 after CcyberCchallenge.IT (an italian prooramme for young and {backspace}{backspace}{backspace}{backspace}boys and girls betwen {backspace}{backspace}en 16 and 24({backspace}) at Uniiersiti{backspace}y of CAa, in Ssardinia.←←←←←←←←←←←←←←←agliari↓→
Our name comes from the union between Ssardinia (srdn({backspace}_{backspace}) annnd{backspace}{backspace}d strnlen().
In 2021, accird{backspace}{backspace}{backspace}ording tt CTF time, we are rated as 3rd in italiank ra{backspace}{backspace}{backspace}{backspace} ranking and 81tt overall.
Aanyway {backspace}{backspace},{backspace}y, here is yyur flag:
srdnlen{Us8?{backspace}_tr4ffic←{backspace}1←←←←←←[CAPSLOCK]t[CAPSLOCK]→?1{backspace}{backspace}_1Ss_Ff{backspace}fu{backspace}{backspace}{backspace}Ffun_to_[CAPSLOCK]d3c0[CAPSLOCK]d3←←←←←←←←→{backspace}{backspace}T0↓}

Aa si biri ;)
```


##### Flag 

**srdnlen{US8_Tr4ff1c_1S_Fun_T0_D3C0d3}**
