# 1. JoyDivision

> The challenge contains two files named 'disorder' and 'flag.txt'.

## Solution

- I downloaded the first file: 'disorder' and inspected it using the "file" command. It showed that it was an ELF 64-bit LSB executable file.
- I then ran the file using the command "./disorder" and it printed out the following text with a segmentation fault at the end:

*May Jupiter strike you down Caeser before you seize the treasury!! You will have to tear me apart*
*for me to tell you the flag to unlock the Roman Treasury and fund your civil war. I, Lucius Caecilius*
*Metellus, shall not let you pass until you get this password right. (or threaten to kill me-)*

*Segmentation fault (core dumped)*

- I then opened the 'flag.txt' file to dig deeper but it contained random bytes which indicated that it was probably the encoded flag which the program 'disorder' was outputting.
- Since it was an ELF executable, I opened it up in Ghidra to analyse it further.
- I navigated to the main function and figured out what it did:

``` c
undefined8 main(void)

{
  byte bVar1;
  undefined1 *puVar2;
  void *__ptr;
  int iVar3;
  long lVar4;
  ulong uVar5;
  undefined8 uVar6;
  FILE *pFVar7;
  undefined1 *puVar8;
  long in_FS_OFFSET;
  undefined1 auStack_88 [8];
  int local_80;
  int local_7c;
  FILE *local_78;
  long local_70;
  undefined1 *local_68;
  undefined8 local_60;
  undefined8 local_58;
  void *local_50;
  FILE *local_48;
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "\nMay Jupiter strike you down Caeser before you seize the treasury!! You will have to tear me apart"
      );
  puts(
      "for me to tell you the flag to unlock the Roman Treasury and fund your civil war. I, Lucius Caecilius"
      );
  puts(
      "Metellus, shall not let you pass until you get this password right. (or threaten to kill me-)\n"
      );
  local_78 = fopen("palatinepackflag.txt","r");
  fseek(local_78,0,2);
  lVar4 = ftell(local_78);
  local_7c = (int)lVar4 + 1;
  fseek(local_78,0,0);
  local_70 = (long)local_7c + -1;
  uVar5 = (((long)local_7c + 0xfU) / 0x10) * 0x10;
  for (puVar8 = auStack_88; puVar8 != auStack_88 + -(uVar5 & 0xfffffffffffff000);
      puVar8 = puVar8 + -0x1000) {
    *(undefined8 *)(puVar8 + -8) = *(undefined8 *)(puVar8 + -8);
  }
  lVar4 = -(ulong)((uint)uVar5 & 0xfff);
  if ((uVar5 & 0xfff) != 0) {
    *(undefined8 *)(puVar8 + ((ulong)((uint)uVar5 & 0xfff) - 8) + lVar4) =
         *(undefined8 *)(puVar8 + ((ulong)((uint)uVar5 & 0xfff) - 8) + lVar4);
  }
  pFVar7 = local_78;
  iVar3 = local_7c;
  local_68 = puVar8 + lVar4;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101bfa;
  fgets(puVar8 + lVar4,iVar3,pFVar7);
  puVar2 = local_68;
  iVar3 = local_7c;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c0b;
  flipBits(puVar2,iVar3);
  puVar2 = local_68;
  iVar3 = local_7c;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c1c;
  uVar6 = expand(puVar2,iVar3);
  iVar3 = local_7c * 2;
  local_60 = uVar6;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c34;
  uVar6 = expand(uVar6,iVar3);
  iVar3 = local_7c * 4;
  local_58 = uVar6;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c50;
  local_50 = (void *)expand(uVar6,iVar3);
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c5e;
  anti_debug();
  for (local_80 = 0; local_80 < local_7c * 8; local_80 = local_80 + 1) {
    bVar1 = *(byte *)((long)local_50 + (long)local_80);
    *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c81;
    putchar((uint)bVar1);
  }
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101c9a;
  putchar(10);
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101cb3;
  pFVar7 = fopen("flag.txt","wb");
  __ptr = local_50;
  iVar3 = local_7c << 3;
  local_48 = pFVar7;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101cd5;
  fwrite(__ptr,1,(long)iVar3,pFVar7);
  pFVar7 = local_48;
  *(undefined8 *)(puVar8 + lVar4 + -8) = 0x101ce1;
  fclose(pFVar7);
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}
```

1) It opened a file called "palatinepackflag.txt" in read mode
2) It puts the contents of that file into a buffer
3) It calls a function flipBits() on the buffer.
4) It calls a function expand() three times on the buffer.
5) It calls an anti-debugging function.
6) Prints the final encoded flag into the flag.txt file

- The flipBits() function is as follows:

```c
void flipBits(long param_1,int param_2)

{
  bool bVar1;
  undefined1 local_11;
  undefined4 local_c;

  bVar1 = false;
  local_11 = 0x69;
  for (local_c = 0; local_c < param_2; local_c = local_c + 1) {
    if (bVar1) {
      *(byte *)(param_1 + local_c) = *(byte *)(param_1 + local_c) ^ local_11;
      local_11 = local_11 + 0x20;
    }
    else {
      *(byte *)(param_1 + local_c) = ~*(byte *)(param_1 + local_c);
    }
    bVar1 = !bVar1;
  }
  return;
}
```
1) This function goes over every byte in the buffer
2) param_1 is a pointer to the buffer and param_2 is the size of the buffer. This makes sense since the loop continues until local_c < param_2, i.e., the entire buffer has been covered. The pointer to the current byte is represented by (param_1 + local_c)
2) To bytes at even positions, it applies the bitwise NOT operator ( ~ )
3) To bytes at odd positions, it applies the XOR gate with the inputs as the byte and a key (the key starts at 0x69 and increment by 0x20 every odd bit)
4) The odd and even positions are tracked by the variable bVar1 which is false for even positions and true for odd.
5) The reverse functions of NOT and XOR are the functions themselves which makes it easier to reverse engineer this function

- The function expand() is as follows:

```c
void * expand(long param_1,int param_2)

{
  bool bVar1;
  void *pvVar2;
  byte local_1d;
  int local_18;

  bVar1 = false;
  local_1d = 0x69;
  pvVar2 = malloc((long)(param_2 * 2));
  for (local_18 = 0; local_18 < param_2; local_18 = local_18 + 1) {
    if (bVar1) {
      *(byte *)((long)pvVar2 + (long)(local_18 * 2)) =
           *(byte *)(param_1 + local_18) & 0xf0 | local_1d >> 4;
      *(byte *)((long)pvVar2 + (long)(local_18 * 2) + 1) =
           *(byte *)(param_1 + local_18) & 0xf | local_1d << 4;
    }
    else {
      *(byte *)((long)pvVar2 + (long)(local_18 * 2)) =
           *(byte *)(param_1 + local_18) & 0xf | local_1d << 4;
      *(byte *)((long)pvVar2 + (long)(local_18 * 2) + 1) =
           *(byte *)(param_1 + local_18) & 0xf0 | local_1d >> 4;
    }
    local_1d = local_1d * '\v';
    bVar1 = !bVar1;
  }
  printf("fie");
  return pvVar2;
}



void teehee(void)

{
  size_t __len;

  __len = sysconf(0x1e);
  mprotect((void *)(-__len & 0x1016b9),__len,7);
                    // WARNING: Read-only address (ram,0x001016d6) is written
  uRam00000000001016d6 = 1;
  return;
}
```

1) This function creates a buffer of size (param_2 * 2)
2) Therefore this buffer will contain the space for (param_2 * 2) bytes
3) The function also initialises a variable called local_1d = 0x69 which is basically a key which is multiplied by 11 (ASCII value of '\v') after every iteration of the loop mentioned below
4) The function then, creates a for loop with respect to a variable starting from 0 and ending at (variable < param_2) with unary incrementation after each step
5) Inside the for loop is an if-condition. If the byte bVar1 is true, the function splits the original buffer byte into two: original_high and original_low, and the key byte into two: key_high and key_low. Then, this function concatenates [original_high | key_low] and adds it into the buffer and also concatenates [original_low | key_high] and adds it into the subsequent index in the buffer. If bVar2 is false, then the function does the splitting like in the other case but concatenates [original_low | key_high] and adds it into the buffer and also concatenates [original_high | key_low] and adds it into the subsequent index in the buffer.
5) This doubles the size of the buffer every time the function is called. Since this function is called thrice, the function basically multiples the original size of the buffer by 8. The content of the 'flag.txt' file is of 296 characters, the original flag will be of 37 characters (296 / 8). This is helpful for confirming the obtained flag.
6) The function writes this ouput into the previously created buffer

- I realised that I need to reverse engineer this encoded output stored in 'flag.txt' using something like a python script
- Therefore, I have to undo expand() thrice and undo flipBits() once
- Reverse engineering expand():

```python
def inverse_expand(data):
    new_length = len(data) // 2
    result = bytearray(new_length)

    for i in range(new_length):
        A = data[2 * i]
        B = data[2 * i + 1]

        if i % 2 == 0:
           # Take the upper half from b and lower half from a
            high_half = B & 240
            low_half  = A & 15
            result[i] = high_half | low_half
        else:
          # Take the upper half from a and lower half from
            high_half = A & 240
            low_half  = B & 15
            result[i] = high_half | low_half

    return bytes(result)
```

1) The function sets n (resultant array length) as the original array length divided by 2 since inverse_expand() will divide the size of the original array by 2.
2) The function, takes the upper half from b and lower half from a for even positions and the upper half from a and lower half from b for odd positions.
3) It does this by taking the and gate with 240 for the uppera half and 15 for the lower half. For example, 240 in binary is 1111000 and suppose b = 43 = 00101011. Then, taking bitwise AND between them will give 00100000 which is the upper half of b.

- Reverse engineering flipBits():

```python
def undo_flipBits(data):
    result = bytearray()
    key = 105 # 0x69 in decimal

    for i in range(len(data)):
        byte = data[i]

        if i % 2 == 0:
            result.append(~byte & 255)
        else:
            result.append(byte ^ key)
            key = (key + 32) % 256

    return bytes(result)
```
1) The function creates a resultant bytearray() to store the results
2) It initialises a key = 105 (0x69), which it increments by 32 (0x20) every iteration
3) For bytes at even positions, the function flips all bits in the byte
4) For bytes at odd positions, the function XORs the input bytes with the key

- Final python script:

```python
def inverse_expand(data):
    new_length = len(data) // 2
    result = bytearray(new_length)

    for i in range(new_length):
        A = data[2 * i]
        B = data[2 * i + 1]

        if i % 2 == 0:
            high_half = B & 240
            low_half  = A & 15
            result[i] = high_half | low_half
        else:
            high_half = A & 240
            low_half  = B & 15
            result[i] = high_half | low_half

    return bytes(result)


def undo_flipBits(data):
    result = bytearray()
    key = 105

    for i in range(len(data)):
        byte = data[i]

        if i % 2 == 0:
            result.append(~byte & 255)
        else:
            result.append(byte ^ key)
            key = (key + 32) % 256

    return bytes(result)


cipher = open("flag.txt", "rb").read()

step1 = inverse_expand(cipher)
step2 = inverse_expand(step1)
step3 = inverse_expand(step2)

original = undo_flipBits(step3)

print(original.decode(errors="ignore"))
```

## Flag

```
sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}
```

## Concepts learnt

- Learnt simple binary operations like bitwise NOT and bitwise XOR and how to reverse them
- Learnt how to back trace the logic of functions to reverse engineer them
- Learnt how to write python scripts

## Notes

- The binary included some extra functions like rotate_block_left() and doWeirdStuff(), but these were never actually called in main which lead me to believe that they were there for distraction
- The program also had an anti-debug check, but static analysis in Ghidra allowed me to ignore it safely
- The flag obtained is of 37 characters which is matching up with the predicted size

## Resources

- [Decompiler Explorer](https://dogbolt.org/?id=d96ad254-edc3-4a13-ac38-ab4ade6aa23b#Ghidra=134)
- [RapidTables - Denary to Binary converter](https://www.rapidtables.com/convert/number/decimal-to-binary.html?x=43)
- [UTF-8 string length & byte counter](https://mothereff.in/byte-counter)


# 2. worthy.knight

> The challenge contains a single file named 'worthy.knight'

## Solution

- I downloaded the file disorder' and inspected it using the "file" command. It turned out to be a 64-bit ELF pie executable
- Like done in the previous challenge, I put the binary into Ghidra for further analysis
- I figured out that the main part of the code lies in a function called 'FUN_001010d0()'
- The function essentially does the following things:

1) Upon code execution, the code prints out some roman-style text and then asks for input
2) The input received is check for its length. It is rejected if the input length is anything other than 10 characters
3) C0 and C1 are XOR'ed with C1 fixed and cross-checks that output against a predetermined value
4) C2 and C3 are XOR'ed with C3 fixed and cross-checks that output against a predetermined value
5) A special function is applied on C4 and C5. This is a hash function which basically calculates the MD5 hash of the 16-bit value obtained from the concatenated characters C5 and C4. It then compares this hash against a predetermined hash.
6) C6 and C7 are XOR'ed with C7 fixed and cross-checks that output against a predetermined value
7) C8 and C9 are XOR'ed with C9 fixed and cross-checks that output against a predetermined value
8) If all the above conditions are true then the string of 10 characters entered is the flag

- The XOR operations can be easily reversed but a python script has to be written to brute-force the MD5 hashing and comparision to obtain the original characters
- Python script written to brute-force the MD5 hash check:

```python
import hashlib
import string

target = "33a3192ba92b5a4803c9a9ed70ea5a9c"

for c4 in string.ascii_letters:
    for c5 in string.ascii_letters:
        if hashlib.md5((c5 + c4).encode()).hexdigest() == target:
            print(c4, c5)
```
- Output:

```ngin
f T
```

- Reversing the XOR operations and brute-forcing the MD5 hashing gives the values of the characters as the following:

1) C0 = N
2) C1 = j
3) C2 = k
4) C3 = S
5) C4 = f
6) C5 = T
7) C6 = Y
8) C7 = a
9) C8 = I
10) C9 = i

- Therefore, the flag obtained is KCTF{NjkSfTYaIi}

![Program output when the input satisfies all conditions](<Challenge Assets/worthy.knight/worthy.knight.png>)

## Flag

```
KCTF{NjkSfTYaIi}
```

## Concepts learnt

- Learnt how to write brute-forcing scripts to crack simple checks using hashing like MD5 hashing
- Learnt how to reconstruct strings given the constraits it needs to adhere to

## Notes

- The input length has to be exactly 10 characters (newline is removed using strcspn())
- The program splits the 10 characters into 5 pairs and each of them have to adhere to the following conditions:

1) must be alphanumeric
2) they have to be of mixed cases (both cannot be uppercase or lowercase)

## Resources

- [Decompiler Explorer](https://dogbolt.org/?id=d96ad254-edc3-4a13-ac38-ab4ade6aa23b#Ghidra=134)
- [RapidTables - Hex to String converter](https://www.rapidtables.com/convert/number/decimal-to-binary.html?x=43)
- [Bitwise Calculator](https://codebeautify.org/bitwise-calculator)


# 3. time

> The challenge contains a single file named 'time'

## Solution

- I downloaded the file 'time' and inspected it using the "file" command. It turned out to be a 64-bit ELF executable like the files in the previous challenges
- Like done in the previous challenges, I put the binary into Ghidra for further analysis
- I have attached the decompiled main function below:

```c
undefined8 main(void)

{
  time_t tVar1;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  puts("Welcome to the number guessing game!");
  puts("I\'m thinking of a number. Can you guess it?");
  puts("Guess right and you get a flag!");
  printf("Enter your number: ");
  fflush(stdout);
  __isoc99_scanf(&DAT_00400bbc,&local_18);
  printf("Your guess was %u.\n",(ulong)local_18);
  printf("Looking for %u.\n",(ulong)local_14);
  fflush(stdout);
  if (local_14 == local_18) {
    puts("You won. Guess was right! Here\'s your flag:");
    giveFlag();
  }
  else {
    puts("Sorry. Try again, wrong guess!");
  }
  fflush(stdout);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}
```

- The program does the following in the main() function:

1) It seeds the rand() function using srand(time(NULL))
2) It generates a number using rand()
3) It asks the user to input a number
4) The program checks if the input number is equal to the random number generated and prints the number expected regardless of correctness

- This leaves room for a time based exploit
- Since, the function time(NULL) has a time-step of 1 second, the value of time(NULL) will be the same in the same second so rand() will always print the same number regardless of how many times it is called if it is called that many times in the same second
- Therefore, we can run the binary once using a dummy input like 0 to obtain the expected number which the program prints regardless of correctness of the input number
- Then, we can run the binary again in the same second and provide the expected number as input
- This will print the flag since time(NULL) will run only once per second and produce the same rand() value
- The following script can be written to do the above mentioned tasks:

```python
import os

a = os.popen("echo 0 | ./time").read()
n = a.split("Looking for ")[1].split(".")[0]
print(os.popen(f"echo {n} | ./time").read())
```

- This script does the following things:

1) It runs the time program once and gives it a dummy guess (0)
2) It captures everything the program prints in a variable 'a'
3) It looks through the output (variable 'a') to find the line that says "Looking for <expected number>"
4) Extracts the number expected and stores it in a variable called 'n'
5) It runs the program again in the same second and gives it the expected number stored in 'n'
6) It finally prints the output of the second run which will ideally contain the flag

## Flag

```
-
```

## Concepts learnt

- Understood how seeding a psuedo random number generator makes the output produced by rand() predictable
- Learnt how to interact with binaries automatically using python

## Notes

- srand(time(NULL)) changes every second so we have a one second window to interact with the program and get the flag
- The os library in python is useful for such tasks because it allows the user to run shell commands through python code and read the output from the shell and store it in variables and so on

## Resources

- [Decompiler Explorer](https://dogbolt.org/?id=d96ad254-edc3-4a13-ac38-ab4ade6aa23b#Ghidra=134)
- [os — Miscellaneous operating system interfaces](https://docs.python.org/3/library/os.html#os.popen)
- [Pseudo Random Number Generator (PRNG)](https://www.geeksforgeeks.org/dsa/pseudo-random-number-generator-prng/)


# 4. VeridisQuo

> The challenge contains a single file named 'VeridisQuo.apk'

## Solution

- I downloaded the file 'VeridisQuo.apk' and inspected it using the "file" command. It turned out to be an APK (Android Package Kit) file
- I found a tool called jadx to decompile apk files back into human-understandable java-like code
- The decompilation of the APK file resulted in two folders named "Resources" and "Sources"
- I recursively grepped the resources folder for the keyword "flag" and found some pieces of strings mentioning "flagpart1 ....... flagpart28"
- This told me that the flag was probably split into 28 pieces
- I have attached the output obtained when the command "grep -R "flag" resources/" was ran below:

```bash
neelay@Neelays-Laptop:~/Projects/Reverse_Engineering/VeridisQuo/out$ grep -R "flag" resources/
grep: resources/classes3.dex: binary file matches
grep: resources/classes.dex: binary file matches
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart1"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart2"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart3"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart4"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart5"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart6"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart7"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart8"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart9"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart10"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart11"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart12"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart13"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart14"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart15"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart16"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart17"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart18"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart19"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart20"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart21"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart22"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart23"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart24"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart25"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart26"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart27"
resources/res/layout/activity_main.xml:        android:id="@+id/flagPart28"
resources/res/layout/mtrl_picker_text_input_date.xml:            android:imeOptions="flagNoExtractUi"/>
resources/res/layout/mtrl_search_view.xml:                            android:imeOptions="flagNoExtractUi|actionSearch"
resources/res/layout/mtrl_picker_text_input_date_range.xml:                android:imeOptions="flagNoExtractUi"/>
resources/res/layout/mtrl_picker_text_input_date_range.xml:                android:imeOptions="flagNoExtractUi"/>
resources/res/values/public.xml:    <public type="id" name="flagPart1" id="0x7f0800c2" />
resources/res/values/public.xml:    <public type="id" name="flagPart10" id="0x7f0800c3" />
resources/res/values/public.xml:    <public type="id" name="flagPart11" id="0x7f0800c4" />
resources/res/values/public.xml:    <public type="id" name="flagPart12" id="0x7f0800c5" />
resources/res/values/public.xml:    <public type="id" name="flagPart13" id="0x7f0800c6" />
resources/res/values/public.xml:    <public type="id" name="flagPart14" id="0x7f0800c7" />
resources/res/values/public.xml:    <public type="id" name="flagPart15" id="0x7f0800c8" />
resources/res/values/public.xml:    <public type="id" name="flagPart16" id="0x7f0800c9" />
resources/res/values/public.xml:    <public type="id" name="flagPart17" id="0x7f0800ca" />
resources/res/values/public.xml:    <public type="id" name="flagPart18" id="0x7f0800cb" />
resources/res/values/public.xml:    <public type="id" name="flagPart19" id="0x7f0800cc" />
resources/res/values/public.xml:    <public type="id" name="flagPart2" id="0x7f0800cd" />
resources/res/values/public.xml:    <public type="id" name="flagPart20" id="0x7f0800ce" />
resources/res/values/public.xml:    <public type="id" name="flagPart21" id="0x7f0800cf" />
resources/res/values/public.xml:    <public type="id" name="flagPart22" id="0x7f0800d0" />
resources/res/values/public.xml:    <public type="id" name="flagPart23" id="0x7f0800d1" />
resources/res/values/public.xml:    <public type="id" name="flagPart24" id="0x7f0800d2" />
resources/res/values/public.xml:    <public type="id" name="flagPart25" id="0x7f0800d3" />
resources/res/values/public.xml:    <public type="id" name="flagPart26" id="0x7f0800d4" />
resources/res/values/public.xml:    <public type="id" name="flagPart27" id="0x7f0800d5" />
resources/res/values/public.xml:    <public type="id" name="flagPart28" id="0x7f0800d6" />
resources/res/values/public.xml:    <public type="id" name="flagPart3" id="0x7f0800d7" />
resources/res/values/public.xml:    <public type="id" name="flagPart4" id="0x7f0800d8" />
resources/res/values/public.xml:    <public type="id" name="flagPart5" id="0x7f0800d9" />
resources/res/values/public.xml:    <public type="id" name="flagPart6" id="0x7f0800da" />
resources/res/values/public.xml:    <public type="id" name="flagPart7" id="0x7f0800db" />
resources/res/values/public.xml:    <public type="id" name="flagPart8" id="0x7f0800dc" />
resources/res/values/public.xml:    <public type="id" name="flagPart9" id="0x7f0800dd" />
resources/res/values/attrs.xml:        <flag name="META" value="0x10000" />
resources/res/values/attrs.xml:        <flag name="CTRL" value="0x1000" />
resources/res/values/attrs.xml:        <flag name="ALT" value="0x2" />
resources/res/values/attrs.xml:        <flag name="SHIFT" value="0x1" />
resources/res/values/attrs.xml:        <flag name="SYM" value="0x4" />
resources/res/values/attrs.xml:        <flag name="FUNCTION" value="0x8" />
resources/res/values/attrs.xml:        <flag name="peekHeight" value="0x1" />
resources/res/values/attrs.xml:        <flag name="fitToContents" value="0x2" />
resources/res/values/attrs.xml:        <flag name="hideable" value="0x4" />
resources/res/values/attrs.xml:        <flag name="skipCollapsed" value="0x8" />
resources/res/values/attrs.xml:        <flag name="all" value="-1" />
resources/res/values/attrs.xml:        <flag name="none" value="0" />
resources/res/values/attrs.xml:        <flag name="center_vertical" value="0x10" />
resources/res/values/attrs.xml:        <flag name="top" value="0x30" />
resources/res/values/attrs.xml:        <flag name="bottom" value="0x50" />
resources/res/values/attrs.xml:        <flag name="toggle" value="0x11" />
resources/res/values/attrs.xml:        <flag name="transitionToEnd" value="0x1" />
resources/res/values/attrs.xml:        <flag name="transitionToStart" value="0x10" />
resources/res/values/attrs.xml:        <flag name="jumpToEnd" value="0x100" />
resources/res/values/attrs.xml:        <flag name="jumpToStart" value="0x1000" />
resources/res/values/attrs.xml:        <flag name="top" value="0x30" />
resources/res/values/attrs.xml:        <flag name="bottom" value="0x50" />
resources/res/values/attrs.xml:        <flag name="left" value="0x3" />
resources/res/values/attrs.xml:        <flag name="right" value="0x5" />
resources/res/values/attrs.xml:        <flag name="center_vertical" value="0x10" />
resources/res/values/attrs.xml:        <flag name="fill_vertical" value="0x70" />
resources/res/values/attrs.xml:        <flag name="center_horizontal" value="0x1" />
resources/res/values/attrs.xml:        <flag name="center" value="0x11" />
resources/res/values/attrs.xml:        <flag name="start" value="0x800003" />
resources/res/values/attrs.xml:        <flag name="end" value="0x800005" />
resources/res/values/attrs.xml:        <flag name="none" value="0" />
resources/res/values/attrs.xml:        <flag name="useLogo" value="0x1" />
resources/res/values/attrs.xml:        <flag name="showHome" value="0x2" />
resources/res/values/attrs.xml:        <flag name="homeAsUp" value="0x4" />
resources/res/values/attrs.xml:        <flag name="showTitle" value="0x8" />
resources/res/values/attrs.xml:        <flag name="showCustom" value="0x10" />
resources/res/values/attrs.xml:        <flag name="disableHome" value="0x20" />
resources/res/values/attrs.xml:        <flag name="top" value="0x30" />
resources/res/values/attrs.xml:        <flag name="bottom" value="0x50" />
resources/res/values/attrs.xml:        <flag name="left" value="0x3" />
resources/res/values/attrs.xml:        <flag name="right" value="0x5" />
resources/res/values/attrs.xml:        <flag name="center_vertical" value="0x10" />
resources/res/values/attrs.xml:        <flag name="fill_vertical" value="0x70" />
resources/res/values/attrs.xml:        <flag name="center_horizontal" value="0x1" />
resources/res/values/attrs.xml:        <flag name="center" value="0x11" />
resources/res/values/attrs.xml:        <flag name="start" value="0x800003" />
resources/res/values/attrs.xml:        <flag name="end" value="0x800005" />
resources/res/values/attrs.xml:        <flag name="start" value="0x1" />
resources/res/values/attrs.xml:        <flag name="textStart" value="0x2" />
resources/res/values/attrs.xml:        <flag name="end" value="0x3" />
resources/res/values/attrs.xml:        <flag name="textEnd" value="0x4" />
resources/res/values/attrs.xml:        <flag name="top" value="0x10" />
resources/res/values/attrs.xml:        <flag name="textTop" value="0x20" />
resources/res/values/attrs.xml:        <flag name="top" value="0x30" />
resources/res/values/attrs.xml:        <flag name="bottom" value="0x50" />
resources/res/values/attrs.xml:        <flag name="left" value="0x3" />
resources/res/values/attrs.xml:        <flag name="right" value="0x5" />
resources/res/values/attrs.xml:        <flag name="center_vertical" value="0x10" />
resources/res/values/attrs.xml:        <flag name="fill_vertical" value="0x70" />
resources/res/values/attrs.xml:        <flag name="center_horizontal" value="0x1" />
resources/res/values/attrs.xml:        <flag name="fill_horizontal" value="0x7" />
resources/res/values/attrs.xml:        <flag name="center" value="0x11" />
resources/res/values/attrs.xml:        <flag name="fill" value="0x77" />
resources/res/values/attrs.xml:        <flag name="clip_vertical" value="0x80" />
resources/res/values/attrs.xml:        <flag name="clip_horizontal" value="0x8" />
resources/res/values/attrs.xml:        <flag name="start" value="0x800003" />
resources/res/values/attrs.xml:        <flag name="end" value="0x800005" />
resources/res/values/attrs.xml:        <flag name="none" value="0x0" />
resources/res/values/attrs.xml:        <flag name="top" value="0x30" />
resources/res/values/attrs.xml:        <flag name="bottom" value="0x50" />
resources/res/values/attrs.xml:        <flag name="left" value="0x3" />
resources/res/values/attrs.xml:        <flag name="right" value="0x5" />
resources/res/values/attrs.xml:        <flag name="start" value="0x800003" />
resources/res/values/attrs.xml:        <flag name="end" value="0x800005" />
resources/res/values/attrs.xml:        <flag name="all" value="0x77" />
resources/res/values/attrs.xml:        <flag name="none" value="0" />
resources/res/values/attrs.xml:        <flag name="legacy" value="0" />
resources/res/values/attrs.xml:        <flag name="standard" value="257" />
resources/res/values/attrs.xml:        <flag name="direct" value="1" />
resources/res/values/attrs.xml:        <flag name="barrier" value="2" />
resources/res/values/attrs.xml:        <flag name="chains" value="4" />
resources/res/values/attrs.xml:        <flag name="dimensions" value="8" />
resources/res/values/attrs.xml:        <flag name="ratio" value="16" />
resources/res/values/attrs.xml:        <flag name="groups" value="32" />
resources/res/values/attrs.xml:        <flag name="graph" value="64" />
resources/res/values/attrs.xml:        <flag name="graph_wrap" value="128" />
resources/res/values/attrs.xml:        <flag name="cache_measures" value="256" />
resources/res/values/attrs.xml:        <flag name="dependency_ordering" value="512" />
resources/res/values/attrs.xml:        <flag name="grouping" value="1024" />
resources/res/values/attrs.xml:        <flag name="noScroll" value="0x0" />
resources/res/values/attrs.xml:        <flag name="scroll" value="0x1" />
resources/res/values/attrs.xml:        <flag name="exitUntilCollapsed" value="0x2" />
resources/res/values/attrs.xml:        <flag name="enterAlways" value="0x4" />
resources/res/values/attrs.xml:        <flag name="enterAlwaysCollapsed" value="0x8" />
resources/res/values/attrs.xml:        <flag name="snap" value="0x10" />
resources/res/values/attrs.xml:        <flag name="snapMargins" value="0x20" />
resources/res/values/attrs.xml:        <flag name="none" value="0" />
resources/res/values/attrs.xml:        <flag name="disablePostScroll" value="1" />
resources/res/values/attrs.xml:        <flag name="disableScroll" value="2" />
resources/res/values/attrs.xml:        <flag name="supportScrollUp" value="4" />
resources/res/values/attrs.xml:        <flag name="META" value="0x10000" />
resources/res/values/attrs.xml:        <flag name="CTRL" value="0x1000" />
resources/res/values/attrs.xml:        <flag name="ALT" value="0x2" />
resources/res/values/attrs.xml:        <flag name="SHIFT" value="0x1" />
resources/res/values/attrs.xml:        <flag name="SYM" value="0x4" />
resources/res/values/attrs.xml:        <flag name="FUNCTION" value="0x8" />
resources/res/values/attrs.xml:        <flag name="never" value="0" />
resources/res/values/attrs.xml:        <flag name="ifRoom" value="1" />
resources/res/values/attrs.xml:        <flag name="always" value="2" />
resources/res/values/attrs.xml:        <flag name="withText" value="4" />
resources/res/values/attrs.xml:        <flag name="collapseActionView" value="8" />
resources/res/values/attrs.xml:        <flag name="none" value="0" />
resources/res/values/attrs.xml:        <flag name="beginning" value="1" />
resources/res/values/attrs.xml:        <flag name="middle" value="2" />
resources/res/values/attrs.xml:        <flag name="end" value="4" />
resources/res/values/attrs.xml:        <flag name="overshoot" value="0" />
resources/res/values/attrs.xml:        <flag name="bounceStart" value="1" />
resources/res/values/attrs.xml:        <flag name="bounceEnd" value="2" />
resources/res/values/attrs.xml:        <flag name="bounceBoth" value="3" />
resources/res/values/attrs.xml:        <flag name="none" value="0" />
resources/res/values/attrs.xml:        <flag name="beginOnFirstDraw" value="1" />
resources/res/values/attrs.xml:        <flag name="disableIntraAutoTransition" value="2" />
resources/res/values/attrs.xml:        <flag name="onInterceptTouchReturnSwipe" value="4" />
grep: resources/classes2.dex: binary file matches
```

- I noticed that the resources folder does not contain the actual flag pieces but it does contain identifiers for each of the flag pieces
- Therefore, if I can find out where these identifiers are being referenced, I might be able to get the actual flag pieces
- So, I grepped the only other available folder called sources
- I ran the command "grep -R -C3 "flagPart" sources/" (-C3 because it would be helpful to get some lines of context)
- This is the output when the above command was ran:

```bash
sources/byuctf/downwiththefrench/Utilities.java-    }
sources/byuctf/downwiththefrench/Utilities.java-
sources/byuctf/downwiththefrench/Utilities.java-    public void cleanUp() {
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag = (TextView) this.activity.findViewById(R.id.flagPart1);
sources/byuctf/downwiththefrench/Utilities.java-        flag.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag2 = (TextView) this.activity.findViewById(R.id.flagPart2);
sources/byuctf/downwiththefrench/Utilities.java-        flag2.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag3 = (TextView) this.activity.findViewById(R.id.flagPart3);
sources/byuctf/downwiththefrench/Utilities.java-        flag3.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag4 = (TextView) this.activity.findViewById(R.id.flagPart4);
sources/byuctf/downwiththefrench/Utilities.java-        flag4.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag5 = (TextView) this.activity.findViewById(R.id.flagPart5);
sources/byuctf/downwiththefrench/Utilities.java-        flag5.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag6 = (TextView) this.activity.findViewById(R.id.flagPart6);
sources/byuctf/downwiththefrench/Utilities.java-        flag6.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag7 = (TextView) this.activity.findViewById(R.id.flagPart7);
sources/byuctf/downwiththefrench/Utilities.java-        flag7.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag8 = (TextView) this.activity.findViewById(R.id.flagPart8);
sources/byuctf/downwiththefrench/Utilities.java-        flag8.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag9 = (TextView) this.activity.findViewById(R.id.flagPart9);
sources/byuctf/downwiththefrench/Utilities.java-        flag9.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag10 = (TextView) this.activity.findViewById(R.id.flagPart10);
sources/byuctf/downwiththefrench/Utilities.java-        flag10.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag11 = (TextView) this.activity.findViewById(R.id.flagPart11);
sources/byuctf/downwiththefrench/Utilities.java-        flag11.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag12 = (TextView) this.activity.findViewById(R.id.flagPart12);
sources/byuctf/downwiththefrench/Utilities.java-        flag12.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag13 = (TextView) this.activity.findViewById(R.id.flagPart13);
sources/byuctf/downwiththefrench/Utilities.java-        flag13.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag14 = (TextView) this.activity.findViewById(R.id.flagPart14);
sources/byuctf/downwiththefrench/Utilities.java-        flag14.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag15 = (TextView) this.activity.findViewById(R.id.flagPart15);
sources/byuctf/downwiththefrench/Utilities.java-        flag15.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag16 = (TextView) this.activity.findViewById(R.id.flagPart16);
sources/byuctf/downwiththefrench/Utilities.java-        flag16.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag17 = (TextView) this.activity.findViewById(R.id.flagPart17);
sources/byuctf/downwiththefrench/Utilities.java-        flag17.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag18 = (TextView) this.activity.findViewById(R.id.flagPart18);
sources/byuctf/downwiththefrench/Utilities.java-        flag18.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag19 = (TextView) this.activity.findViewById(R.id.flagPart19);
sources/byuctf/downwiththefrench/Utilities.java-        flag19.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag20 = (TextView) this.activity.findViewById(R.id.flagPart20);
sources/byuctf/downwiththefrench/Utilities.java-        flag20.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag21 = (TextView) this.activity.findViewById(R.id.flagPart21);
sources/byuctf/downwiththefrench/Utilities.java-        flag21.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag22 = (TextView) this.activity.findViewById(R.id.flagPart22);
sources/byuctf/downwiththefrench/Utilities.java-        flag22.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag23 = (TextView) this.activity.findViewById(R.id.flagPart23);
sources/byuctf/downwiththefrench/Utilities.java-        flag23.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag24 = (TextView) this.activity.findViewById(R.id.flagPart24);
sources/byuctf/downwiththefrench/Utilities.java-        flag24.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag25 = (TextView) this.activity.findViewById(R.id.flagPart25);
sources/byuctf/downwiththefrench/Utilities.java-        flag25.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag26 = (TextView) this.activity.findViewById(R.id.flagPart26);
sources/byuctf/downwiththefrench/Utilities.java-        flag26.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag27 = (TextView) this.activity.findViewById(R.id.flagPart27);
sources/byuctf/downwiththefrench/Utilities.java-        flag27.setText("");
sources/byuctf/downwiththefrench/Utilities.java:        TextView flag28 = (TextView) this.activity.findViewById(R.id.flagPart28);
sources/byuctf/downwiththefrench/Utilities.java-        flag28.setText("");
sources/byuctf/downwiththefrench/Utilities.java-    }
sources/byuctf/downwiththefrench/Utilities.java-}
--
sources/byuctf/downwiththefrench/R.java-    }
sources/byuctf/downwiththefrench/R.java-
sources/byuctf/downwiththefrench/R.java-    public static final class id {
sources/byuctf/downwiththefrench/R.java:        public static int flagPart1 = 0x7f0800c2;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart10 = 0x7f0800c3;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart11 = 0x7f0800c4;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart12 = 0x7f0800c5;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart13 = 0x7f0800c6;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart14 = 0x7f0800c7;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart15 = 0x7f0800c8;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart16 = 0x7f0800c9;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart17 = 0x7f0800ca;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart18 = 0x7f0800cb;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart19 = 0x7f0800cc;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart2 = 0x7f0800cd;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart20 = 0x7f0800ce;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart21 = 0x7f0800cf;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart22 = 0x7f0800d0;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart23 = 0x7f0800d1;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart24 = 0x7f0800d2;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart25 = 0x7f0800d3;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart26 = 0x7f0800d4;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart27 = 0x7f0800d5;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart28 = 0x7f0800d6;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart3 = 0x7f0800d7;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart4 = 0x7f0800d8;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart5 = 0x7f0800d9;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart6 = 0x7f0800da;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart7 = 0x7f0800db;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart8 = 0x7f0800dc;
sources/byuctf/downwiththefrench/R.java:        public static int flagPart9 = 0x7f0800dd;
sources/byuctf/downwiththefrench/R.java-        public static int homeText = 0x7f0800f1;
sources/byuctf/downwiththefrench/R.java-
sources/byuctf/downwiththefrench/R.java-        /* JADX INFO: Added by JADX */
```

- This indicates that each flag part corresponds to a UI element (text view) in the apps layout
- The java code immediately retrieves these TextViews and immediately clears their content
- Therefore, the actual flag contents have to be defined somewhere else
- They are probably defined in the layout XML files themselves where the TextViews can have hardcoded values
- Therefore, I moved onto examining the XML files starting with the main file: ```activity_main.xml``` under ```resources/res/layout```
- I have attached the contents of the file below:

```bash
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android" xmlns:app="http://schemas.android.com/apk/res-auto"
    android:layout_width="match_parent"
    android:layout_height="match_parent">
    <TextView
        android:id="@+id/homeText"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="b"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintHorizontal_bias="0.066"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintVertical_bias="0.022"/>
    <TextView
        android:id="@+id/flagPart1"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="420dp"
        android:text="}"
        android:layout_marginEnd="216dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart2"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="616dp"
        android:text="t"
        android:layout_marginEnd="340dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart3"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="556dp"
        android:text="a"
        android:layout_marginEnd="332dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart4"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="676dp"
        android:text="y"
        android:layout_marginEnd="368dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart5"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="500dp"
        android:text="c"
        android:layout_marginEnd="252dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart6"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="636dp"
        android:text="c"
        android:layout_marginEnd="348dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart7"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="436dp"
        android:text="d"
        android:layout_marginEnd="364dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart8"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="496dp"
        android:text="r"
        android:layout_marginEnd="348dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart9"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="536dp"
        android:text="n"
        android:layout_marginEnd="336dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart10"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="456dp"
        android:text="i"
        android:layout_marginEnd="360dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart11"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="536dp"
        android:text="0"
        android:layout_marginEnd="276dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart12"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="516dp"
        android:text="d"
        android:layout_marginEnd="340dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart13"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="460dp"
        android:text="k"
        android:layout_marginEnd="232dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart14"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="656dp"
        android:text="u"
        android:layout_marginEnd="356dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart15"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="452dp"
        android:text="p"
        android:layout_marginEnd="320dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart16"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="476dp"
        android:text="o"
        android:layout_marginEnd="352dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart17"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="500dp"
        android:text="c"
        android:layout_marginEnd="300dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart18"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="596dp"
        android:text="f"
        android:layout_marginEnd="332dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart19"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="484dp"
        android:text="e"
        android:layout_marginEnd="308dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart20"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="436dp"
        android:text="_"
        android:layout_marginEnd="328dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart21"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="516dp"
        android:text="e"
        android:layout_marginEnd="292dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart22"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="536dp"
        android:text="_"
        android:layout_marginEnd="284dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart23"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="536dp"
        android:text="f"
        android:layout_marginEnd="268dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart24"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="468dp"
        android:text="i"
        android:layout_marginEnd="316dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart25"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="516dp"
        android:text="_"
        android:layout_marginEnd="260dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart26"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="480dp"
        android:text="4"
        android:layout_marginEnd="240dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart27"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="440dp"
        android:text="e"
        android:layout_marginEnd="224dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <TextView
        android:id="@+id/flagPart28"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginBottom="576dp"
        android:text="{"
        android:layout_marginEnd="324dp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
</androidx.constraintlayout.widget.ConstraintLayout>
```

- This finally gives us the actual content in the TextView objects
- Writing these out according to the order in which they are given in the ```activity_main.xml``` file gives:

```
}tayccdrni0dkupocfe_
```

- This does not seem to match up with the conventional flag nomenclature: ```<CTF name>{<flag contents>}```
- Therefore, it seems that the true order of the characters is not determined by the order in which they are written in the XML file but instead by how the TextView elements are arranged on screen in the actual Android layout
- Opening the ```activity_main.xml``` file in Android Studio gives:

![Screenshot of said file opened in Android Studio](<Challenge Assets\VeridisQuo\main_layout_android_studio.png>)

- This gives the correct order of characters as:

```
byuctf{android_piece_of_c4ke}
```

- The flag is hence obtained

## Flag

```
byuctf{android_piece_of_c4ke}
```

## Concepts learnt

- Learnt the APK file structure
- Learnt how to use tools like JADX for APK decompilation
- Learnt how to reverse engineer XML layouts
- Viewing XML layouts in Android Studio

## Notes

- Visual layout of elements can differ from the order given in the XML code

## Resources

- [APK file: What it is and how does it work?](https://www.browserstack.com/guide/what-is-an-apk-file)
- [Intro to Android Mobile Reverse Engineering](https://www.corellium.com/blog/android-mobile-reverse-engineering)
- [JADX - Dex to Java decompiler](https://github.com/skylot/jadx)
- [JADX basic tutorial - YouTube](https://youtu.be/QlpDMmfOUmM?si=EGnveLFE76CCgXvB)
- [Android Studio](https://developer.android.com/studio)


# 5. Dusty
## A) Noob
> This challenge contains a single file named "dust_noob"
## Solution
- I downloaded the file 'dust_noob' and inspected it using the "file" command. It turned out to be a 64-bit ELF binary executable
```bash
neelay@Neelays-Laptop:~/Projects/Reverse_Engineering/Dusty$ file dust_noob
dust_noob: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0e91c3247b82497c448e69060be605936f5f06fe, for GNU/Linux 3.2.0, not stripped
```

- I ran the binary and it printed the following:

```bash
neelay@Neelays-Laptop:~/Projects/Reverse_Engineering/Dusty$ ./dust_noob
Shiny Clean™ Rust Remover Budget Edition! Looks like you didn't win this time! Try again?
```

- This seemed to lead nowhere so I decompiled the binary using Ghidra for further analysis
- I navigated to the main program

```c
/* shinyclean::main */

void __rustcall shinyclean::main(void)

{
  int iVar1;
  ulong uVar2;
  byte local_de [23];
  byte local_c7 [23];
  ulong local_b0;
  undefined1 local_a8 [48];
  byte *local_78;
  code *local_70;
  byte *local_68;
  code *local_60;
  undefined1 local_58 [48];
  byte *local_28;
  code *local_20;
  byte *local_18;
  code *local_10;
  byte *local_8;

  memset(local_de,0,0x17);
  local_c7[0] = 0x7b;
  local_c7[1] = 0x5e;
  local_c7[2] = 0x48;
  local_c7[3] = 0x58;
  local_c7[4] = 0x7c;
  local_c7[5] = 0x6b;
  local_c7[6] = 0x79;
  local_c7[7] = 0x44;
  local_c7[8] = 0x79;
  local_c7[9] = 0x6d;
  local_c7[10] = 0xc;
  local_c7[0xb] = 0xc;
  local_c7[0xc] = 0x60;
  local_c7[0xd] = 0x7c;
  local_c7[0xe] = 0xb;
  local_c7[0xf] = 0x6d;
  local_c7[0x10] = 0x60;
  local_c7[0x11] = 0x68;
  local_c7[0x12] = 0xb;
  local_c7[0x13] = 10;
  local_c7[0x14] = 0x77;
  local_c7[0x15] = 0x1e;
  local_c7[0x16] = 0x42;
  local_b0 = 0;
  while( true ) {
    if (0x16 < local_b0) {
                    /* WARNING: Subroutine does not return */
      core::panicking::panic_bounds_check(local_b0,0x17,&PTR_DAT_00154578);
    }
    if (0x16 < local_b0) {
                    /* WARNING: Subroutine does not return */
      core::panicking::panic_bounds_check(local_b0,0x17,&PTR_DAT_00154590);
    }
    local_de[local_b0] = local_c7[local_b0] ^ 0x3f;
    uVar2 = local_b0 + 1;
    if (0xfffffffffffffffe < local_b0) break;
    local_b0 = uVar2;
    if (uVar2 == 0x17) {
LAB_00107c83:
      iVar1 = std::process::id();
      if (iVar1 == 0x1c1e8b2) {
        local_18 = local_de;
        local_10 = core::array::_<>::fmt;
        local_8 = local_de;
        local_78 = local_de;
        local_20 = core::array::_<>::fmt;
        local_60 = core::array::_<>::fmt;
        local_70 = core::array::_<>::fmt;
        local_68 = local_78;
        local_28 = local_78;
        core::fmt::Arguments::new_v1(local_a8,&DAT_001545c0,&local_78);
        std::io::stdio::_print(local_a8);
      }
      else {
        core::fmt::Arguments::new_const(local_58,&PTR_DAT_001545e0);
        std::io::stdio::_print(local_58);
      }
      return;
    }
  }
  core::panicking::panic_const::panic_const_add_overflow(&PTR_DAT_001545a8);
  goto LAB_00107c83;
}
```

- It immediately revealed two arrays being declared and initialized: one was a 23-byte array with hardcoded values and the other was a 23-byte array initialized to all zeros

```c
  byte local_de [23];
  byte local_c7 [23];

  memset(local_de,0,0x17);
  local_c7[0] = 0x7b;
  local_c7[1] = 0x5e;
  local_c7[2] = 0x48;
  local_c7[3] = 0x58;
  local_c7[4] = 0x7c;
  local_c7[5] = 0x6b;
  local_c7[6] = 0x79;
  local_c7[7] = 0x44;
  local_c7[8] = 0x79;
  local_c7[9] = 0x6d;
  local_c7[10] = 0xc;
  local_c7[0xb] = 0xc;
  local_c7[0xc] = 0x60;
  local_c7[0xd] = 0x7c;
  local_c7[0xe] = 0xb;
  local_c7[0xf] = 0x6d;
  local_c7[0x10] = 0x60;
  local_c7[0x11] = 0x68;
  local_c7[0x12] = 0xb;
  local_c7[0x13] = 10;
  local_c7[0x14] = 0x77;
  local_c7[0x15] = 0x1e;
  local_c7[0x16] = 0x42;
```
- I assumed these hex values to be ASCII and converted them to characters which gave this:

```
{^HX|kyDy m␌␌`|␋m`h␋
w␞B
```

- This did not make much sense which lead me to believe that this might be the encoded version of the flag
- The code also performs an array out-of-bounds check between the two array declarations and initializations but this seems irrelevant to the challenge as the loop only iterates from 0 to 22
- The code then XOR's the hardcoded array elements with a fixed constant (0x3f) and stores the values into the local_de[] array
- This means that the local_de[] array probably stores the decoded flag
- The counter then increments by 1

```c
    local_de[local_b0] = local_c7[local_b0] ^ 0x3f;
    uVar2 = local_b0 + 1;
```

- The code then includes a default integer overflow check implemented by rust (irrelevant to the challenge)
- Then the important part of the code appears

```c
      iVar1 = std::process::id();
      if (iVar1 == 0x1c1e8b2) {
        local_18 = local_de;
        local_10 = core::array::_<>::fmt;
        local_8 = local_de;
        local_78 = local_de;
        local_20 = core::array::_<>::fmt;
        local_60 = core::array::_<>::fmt;
        local_70 = core::array::_<>::fmt;
        local_68 = local_78;
        local_28 = local_78;
        core::fmt::Arguments::new_v1(local_a8,&DAT_001545c0,&local_78);
        std::io::stdio::_print(local_a8);
      }
      else {
        core::fmt::Arguments::new_const(local_58,&PTR_DAT_001545e0);
        std::io::stdio::_print(local_58);
      }
```

- Essentially, it assigns the process id of the running program to a variable (Ghidra names it iVar1)
- Then, it checks if the PID is equal to a hardcoded value (0x1c1e8b2)
- This number is impractically large (29,485,234 in denary)
- No PID will be this big
- Therefore, this condition will never be true
- If the conditions is true then the program prints the contents of local_de[] (the decoded flag)
- If the condition is false then the program prints the below mentioned message: (which we have seen before)

```bash
Shiny Clean™ Rust Remover Budget Edition! Looks like you didn't win this time!
```
- Therefore, a simple fix to this problem is using a debugger like GDB to pause the program and insert the required 'PID' value (0x1c1e8b2) into iVar1 and resuming the program
- This should ideally get us the flag
- To do this, I opened up the file in GDB
- Then, I found out all functions with 'main' in their name

```bash
pwndbg> info functions main
All functions matching regular expression "main":

Non-debugging symbols:
0x0000000000007b40  shinyclean::main
0x0000000000007d70  main
0x000000000000b430  core::slice::sort::stable::driftsort_main
0x000000000000b580  core::slice::sort::stable::driftsort_main
0x000000000000b6c0  core::slice::sort::stable::driftsort_main
0x000000000000b800  core::slice::sort::stable::driftsort_main
0x000000000000b940  core::slice::sort::stable::driftsort_main
```

- I found the actual main function: shinyclean::main
- Then set a breakpoint there

```bash
pwndbg> b shinyclean::main
Breakpoint 1 at 0x7b40
```

- Then, I ran the program
- It ran till the 'shinyclean::main' main and then printed the register values, stack content, etc
- I inspected the disassembly using the 'disassemble' command

```bash
pwndbg> disassemble
Dump of assembler code for function _ZN10shinyclean4main17h4b15dd54e331d693E:
=> 0x000055555555bb40 <+0>:     sub    rsp,0x108
   0x000055555555bb47 <+7>:     lea    rdi,[rsp+0x2a]
   0x000055555555bb4c <+12>:    xor    esi,esi
   0x000055555555bb4e <+14>:    mov    edx,0x17
   0x000055555555bb53 <+19>:    call   0x55555555a050 <memset@plt>
   0x000055555555bb58 <+24>:    mov    BYTE PTR [rsp+0x41],0x7b
   0x000055555555bb5d <+29>:    mov    BYTE PTR [rsp+0x42],0x5e
   0x000055555555bb62 <+34>:    mov    BYTE PTR [rsp+0x43],0x48
   0x000055555555bb67 <+39>:    mov    BYTE PTR [rsp+0x44],0x58
   0x000055555555bb6c <+44>:    mov    BYTE PTR [rsp+0x45],0x7c
   0x000055555555bb71 <+49>:    mov    BYTE PTR [rsp+0x46],0x6b
   0x000055555555bb76 <+54>:    mov    BYTE PTR [rsp+0x47],0x79
   0x000055555555bb7b <+59>:    mov    BYTE PTR [rsp+0x48],0x44
   0x000055555555bb80 <+64>:    mov    BYTE PTR [rsp+0x49],0x79
   0x000055555555bb85 <+69>:    mov    BYTE PTR [rsp+0x4a],0x6d
   0x000055555555bb8a <+74>:    mov    BYTE PTR [rsp+0x4b],0xc
   0x000055555555bb8f <+79>:    mov    BYTE PTR [rsp+0x4c],0xc
   0x000055555555bb94 <+84>:    mov    BYTE PTR [rsp+0x4d],0x60
   0x000055555555bb99 <+89>:    mov    BYTE PTR [rsp+0x4e],0x7c
   0x000055555555bb9e <+94>:    mov    BYTE PTR [rsp+0x4f],0xb
   0x000055555555bba3 <+99>:    mov    BYTE PTR [rsp+0x50],0x6d
   0x000055555555bba8 <+104>:   mov    BYTE PTR [rsp+0x51],0x60
   0x000055555555bbad <+109>:   mov    BYTE PTR [rsp+0x52],0x68
   0x000055555555bbb2 <+114>:   mov    BYTE PTR [rsp+0x53],0xb
   0x000055555555bbb7 <+119>:   mov    BYTE PTR [rsp+0x54],0xa
   0x000055555555bbbc <+124>:   mov    BYTE PTR [rsp+0x55],0x77
   0x000055555555bbc1 <+129>:   mov    BYTE PTR [rsp+0x56],0x1e
   0x000055555555bbc6 <+134>:   mov    BYTE PTR [rsp+0x57],0x42
   0x000055555555bbcb <+139>:   mov    QWORD PTR [rsp+0x58],0x0
   0x000055555555bbd4 <+148>:   mov    rax,QWORD PTR [rsp+0x58]
   0x000055555555bbd9 <+153>:   mov    QWORD PTR [rsp+0x20],rax
   0x000055555555bbde <+158>:   cmp    rax,0x17
   0x000055555555bbe2 <+162>:   jae    0x55555555bc03 <_ZN10shinyclean4main17h4b15dd54e331d693E+195>
   0x000055555555bbe4 <+164>:   mov    rax,QWORD PTR [rsp+0x20]
   0x000055555555bbe9 <+169>:   mov    al,BYTE PTR [rsp+rax*1+0x41]
   0x000055555555bbed <+173>:   mov    BYTE PTR [rsp+0x17],al
   0x000055555555bbf1 <+177>:   mov    rax,QWORD PTR [rsp+0x58]
   0x000055555555bbf6 <+182>:   mov    QWORD PTR [rsp+0x18],rax
   0x000055555555bbfb <+187>:   cmp    rax,0x17
   0x000055555555bbff <+191>:   jb     0x55555555bc1d <_ZN10shinyclean4main17h4b15dd54e331d693E+221>
   0x000055555555bc01 <+193>:   jmp    0x55555555bc42 <_ZN10shinyclean4main17h4b15dd54e331d693E+258>
   0x000055555555bc03 <+195>:   mov    rdi,QWORD PTR [rsp+0x20]
   0x000055555555bc08 <+200>:   lea    rdx,[rip+0x4c969]        # 0x5555555a8578
   0x000055555555bc0f <+207>:   lea    rax,[rip+0xfffffffffffff71f]        # 0x55555555b335 <_ZN4core9panicking18panic_bounds_check17h8307ccead484a122E>
   0x000055555555bc16 <+214>:   mov    esi,0x17
   0x000055555555bc1b <+219>:   call   rax
   0x000055555555bc1d <+221>:   mov    rax,QWORD PTR [rsp+0x18]
   0x000055555555bc22 <+226>:   mov    cl,BYTE PTR [rsp+0x17]
   0x000055555555bc26 <+230>:   xor    cl,0x3f
   0x000055555555bc29 <+233>:   mov    BYTE PTR [rsp+rax*1+0x2a],cl
   0x000055555555bc2d <+237>:   mov    rax,QWORD PTR [rsp+0x58]
   0x000055555555bc32 <+242>:   add    rax,0x1
   0x000055555555bc36 <+246>:   mov    QWORD PTR [rsp+0x8],rax
   0x000055555555bc3b <+251>:   setb   al
   0x000055555555bc3e <+254>:   jb     0x55555555bc73 <_ZN10shinyclean4main17h4b15dd54e331d693E+307>
   0x000055555555bc40 <+256>:   jmp    0x55555555bc5c <_ZN10shinyclean4main17h4b15dd54e331d693E+284>
   0x000055555555bc42 <+258>:   mov    rdi,QWORD PTR [rsp+0x18]
   0x000055555555bc47 <+263>:   lea    rdx,[rip+0x4c942]        # 0x5555555a8590
   0x000055555555bc4e <+270>:   lea    rax,[rip+0xfffffffffffff6e0]        # 0x55555555b335 <_ZN4core9panicking18panic_bounds_check17h8307ccead484a122E>
   0x000055555555bc55 <+277>:   mov    esi,0x17
   0x000055555555bc5a <+282>:   call   rax
   0x000055555555bc5c <+284>:   mov    rax,QWORD PTR [rsp+0x8]
   0x000055555555bc61 <+289>:   mov    QWORD PTR [rsp+0x58],rax
   0x000055555555bc66 <+294>:   cmp    QWORD PTR [rsp+0x58],0x17
   0x000055555555bc6c <+300>:   je     0x55555555bc83 <_ZN10shinyclean4main17h4b15dd54e331d693E+323>
   0x000055555555bc6e <+302>:   jmp    0x55555555bbd4 <_ZN10shinyclean4main17h4b15dd54e331d693E+148>
   0x000055555555bc73 <+307>:   lea    rdi,[rip+0x4c92e]        # 0x5555555a85a8
   0x000055555555bc7a <+314>:   lea    rax,[rip+0xfffffffffffffb9f]        # 0x55555555b820 <_ZN4core9panicking11panic_const24panic_const_add_overflow17hf2f4fb688348b3b0E>
   0x000055555555bc81 <+321>:   call   rax
   0x000055555555bc83 <+323>:   call   QWORD PTR [rip+0x4ef07]        # 0x5555555aab90
   0x000055555555bc89 <+329>:   cmp    eax,0x1c1e8b2
   0x000055555555bc8e <+334>:   jne    0x55555555bd3f <_ZN10shinyclean4main17h4b15dd54e331d693E+511>
   0x000055555555bc94 <+340>:   lea    rax,[rsp+0x2a]
   0x000055555555bc99 <+345>:   mov    QWORD PTR [rsp+0xf0],rax
   0x000055555555bca1 <+353>:   lea    rax,[rip+0xe8]        # 0x55555555bd90 <_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hf6f6e41e4948d91cE>
   0x000055555555bca8 <+360>:   mov    QWORD PTR [rsp+0xf8],rax
   0x000055555555bcb0 <+368>:   lea    rax,[rsp+0x2a]
   0x000055555555bcb5 <+373>:   mov    QWORD PTR [rsp+0x100],rax
   0x000055555555bcbd <+381>:   lea    rax,[rsp+0x2a]
   0x000055555555bcc2 <+386>:   mov    QWORD PTR [rsp+0xe0],rax
   0x000055555555bcca <+394>:   lea    rax,[rip+0xbf]        # 0x55555555bd90 <_ZN4core5array69_$LT$impl$u20$core..fmt..Debug$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$3fmt17hf6f6e41e4948d91cE>
   0x000055555555bcd1 <+401>:   mov    QWORD PTR [rsp+0xe8],rax
   0x000055555555bcd9 <+409>:   mov    rax,QWORD PTR [rsp+0xe0]
   0x000055555555bce1 <+417>:   mov    QWORD PTR [rsp+0xa0],rax
   0x000055555555bce9 <+425>:   mov    rax,QWORD PTR [rsp+0xe8]
   0x000055555555bcf1 <+433>:   mov    QWORD PTR [rsp+0xa8],rax
   0x000055555555bcf9 <+441>:   mov    rax,QWORD PTR [rsp+0xa0]
   0x000055555555bd01 <+449>:   mov    QWORD PTR [rsp+0x90],rax
   0x000055555555bd09 <+457>:   mov    rax,QWORD PTR [rsp+0xa8]
   0x000055555555bd11 <+465>:   mov    QWORD PTR [rsp+0x98],rax
   0x000055555555bd19 <+473>:   lea    rdi,[rsp+0x60]
   0x000055555555bd1e <+478>:   lea    rsi,[rip+0x4c89b]        # 0x5555555a85c0
   0x000055555555bd25 <+485>:   lea    rdx,[rsp+0x90]
   0x000055555555bd2d <+493>:   call   0x55555555be90 <_ZN4core3fmt9Arguments6new_v117hfac9ebf3d99d1264E>
   0x000055555555bd32 <+498>:   lea    rdi,[rsp+0x60]
   0x000055555555bd37 <+503>:   call   QWORD PTR [rip+0x4ee43]        # 0x5555555aab80
   0x000055555555bd3d <+509>:   jmp    0x55555555bd61 <_ZN10shinyclean4main17h4b15dd54e331d693E+545>
   0x000055555555bd3f <+511>:   lea    rdi,[rsp+0xb0]
   0x000055555555bd47 <+519>:   lea    rsi,[rip+0x4c892]        # 0x5555555a85e0
   0x000055555555bd4e <+526>:   call   0x55555555bed0 <_ZN4core3fmt9Arguments9new_const17hf72ed85907e377bbE>
   0x000055555555bd53 <+531>:   lea    rdi,[rsp+0xb0]
   0x000055555555bd5b <+539>:   call   QWORD PTR [rip+0x4ee1f]        # 0x5555555aab80
   0x000055555555bd61 <+545>:   add    rsp,0x108
   0x000055555555bd68 <+552>:   ret
End of assembler dump.
```

- I scrolled until I saw the important line:

```bash
0x55555555bc89 <+329>: cmp eax, 0x1c1e8b2
```

- This line contains the PID check
- I inspected the lines above and below to gain context
- I figured out that if the value of the eax register does not match the desired value then the program jumps to the failure condition branch
- Therefore, I set a breakpoint at the compare line

```bash
b *0x55555555bc89
```

- I continued the program with 'c' until it stopped at the second break point (set at the line where the comparision takes place)
- At this breakpoint, PwnDBG showed the actual PID of the program (RAX = 0x3088)
- This is clearly not equal to the set number and therefore the program would jump to the failure branch had the program not been paused
- At this point, PwnDBG displays the flag in the stack contents section but I proceeded to complete the exploit anyway for convention
- I overwrote the PID value in EAX with the desired number

```bash
set $eax = 0x1c1e8b2
```

- Therefore, the comparision becomes true and the conditional jump does not occur
- The program continues to print the decoded bytes

```bash
Continuing.
[68, 97, 119, 103, 67, 84, 70, 123, 70, 82, 51, 51, 95, 67, 52, 82, 95, 87, 52, 53, 72, 33, 125]
[Inferior 1 (process 12424) exited normally]
```

- Assuming that the bytes are ASCII, converting them to the characters gives:

```
DawgCTF{FR33_C4R_W45H!}
```

- This is the flag

## Flag

```
DawgCTF{FR33_C4R_W45H!}
```

## Concepts learnt

- Learnt how to analyze decompiled rust binaries
- Learnt how to use debugging software to manipulate register values mid program run
- Learnt how to use Ghidra and GDB in unison (Ghidra gave the logic, GDB gave the way)

## Notes

- Rust binaries look confusing due to their auto-generated panic handling and formatting functions
- PwnDBG makes debugging far easier compared to vanilla GDB

## Resources

- [RapidTables - Hex to Denary converter](https://www.rapidtables.com/convert/number/hex-to-decimal.html)
- [PwnDBG](https://pwndbg.re/stable/features/)
- [x64 Cheat Sheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf)
