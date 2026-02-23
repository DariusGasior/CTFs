# YaraRules0x100 

|Category|Difficulty|Points|Author|
| :---: | :---: | :---: | :---:|
|General Skills|Medium|200|Nandan Desai / syreal|
---

Tags:browser_webshell_solvable

### Description
Dear Threat Intelligence Analyst,
Quick heads up - we stumbled upon a shady executable file on one of our employee's Windows PCs. Good news: the employee didn't take the bait and flagged it to our InfoSec crew.
Seems like this file sneaked past our Intrusion Detection Systems, indicating a fresh threat with no matching signatures in our database.
Can you dive into this file and whip up some YARA rules? We need to make sure we catch this thing if it pops up again.
Thanks a bunch!
The suspicious file can be downloaded [here](suspicious.zip). Unzip the archive with the password *picoctf*
Once you have created the YARA rule/signature, submit your rule file as follows:
*socat -t60 - TCP:standard-pizzas.picoctf.net:64300 < sample.txt*
(In the above command, modify "sample.txt" to whatever filename you use).
When you submit your rule, it will undergo testing with various test cases. If it successfully passes all the test cases, you'll receive your flag.
<details>
  <summary>Hint 1</summary>
The test cases will attempt to match your rule with various variations of this suspicious file, including a packed version, an unpacked version, slight modifications to the file while retaining functionality, etc.
</details>
<details>
  <summary>Hint 2</summary>
Since this is a Windows executable file, some strings within this binary can be "wide" strings. Try declaring your string variables something like *$str = "Some Text" wide ascii* wherever necessary.
</details>
<details>
  <summary>Hint 3</summary>
Your rule should also not generate any false positives (or false negatives). Refine your rule to perfection! One YARA rule file can have multiple rules! Maybe define one rule for Packed binary and another rule for Unpacked binary in the same rule file?
</details>

### [Writeup](writeup.md)
