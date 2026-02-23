# YaraRules0x100
- [YaraRules0x100](#YaraRules0x100)
  - [Summary](#summary)
  - [Walk-through](#walk-through)
  - [Flag](#flag)
  - [Key Takeaways](#key-takeaways)

### Summary
_picoCTF 2025 : General Skills_ | 200pts (Medium)

The goal of this challenge is to create Yara rules to correctly identify a provided _suspicious_ binary. The rules will need to pass a series of checks without resulting in either false positives, or false negatives.

### Walk-through
For this challenge, we are provided with a binary file in a password protected zip archive, and a running instance on which we can test our Yara rules.  

The binary is called ```suspicious.exe``` and running ```file suspicious.exe``` we get the result:\
```suspicious.exe: PE32 executable (GUI) Intel 80386, for MS Windows, UPX compressed```  

We are dealing with a packed (UPX compressed) Windows 32bit executable. Being packed, we may be limited in what strings are available to use in our Yara rules. We run  ```strings``` which does yield some unique strings:  
```
...
==+|
:+.__/|_|\ 
elcome to the YaraRules0x100 cha
llenge!^S.,,
l./(%a
...
```  
Let's build a quick Yara rule file check for the string "YaraRules0x100"  

**sample.txt**
```yara
rule check_string 
{
    strings:
        $txt = "YaraRules0x100" 
    condition:
        $txt
}
```
When uploaded to the challenge instance with the command provided in the description  
```
socat -t60 - TCP:standard-pizzas.picoctf.net:56046 < sample.txt
```
we get the output  
```
:::::

Status: Failed
False Negatives Check: Testcase failed. Your rule generated a false negative.
False Positives Check: Testcase failed. Your rule generated a false positive.
Stats: 62 testcase(s) passed. 1 failed. 1 testcase(s) unchecked. 64 total testcases.
Pass all the testcases to get the flag.

:::::

```
We can see this was a promising start. We now know there are 64 total checks, and that our simple test made it through most of them, albeit with both false negatives and false positives.  
Our strategy will be to work on a set of items to test and keep track of how many checks each item passes without any false negatives or false positives. We'll then work on combinations of items in the condition of our rule to try and pass all 64 checks.  
To begin, let's also look for wide strings since this is a Windows binary. We can do that with the **-e l**  option
```
strings -e l suspicious.exe
gnore)
lp32
```
Let's try "lp32" as a wide string.
```yara
rule check_string 
{
    strings:
        $txt = "lp32" wide 
    condition:
        $txt
}
```
Surprisingly, that results in the flag!
```
:::::

Status: Passed
Congrats! Here is your flag: picoCTF{***}

:::::
```
### Flag
<details>
  <summary>Click to reveal the flag</summary>
picoCTF{yara_rul35_r0ckzzz_deb7eedc}
</details>

### Key Takeaways
While we were fortunate to solve the challenge with a very simple rule. In practice, Yara rules can be much more complex. String matching has capabilities like case matching, wildcards, hex patterns, base64 encoding, and regex to name a few. Modules, such as **pe**, can be imported to do more advance structural matching like finding imports from libraries. All of these matching capabilities can be combined in various ways in the condition portion of the rule to create flexible detections.