---
layout: post
title:  "CyberSecurityRumble2021 FlagCheckerBaby"
date:   2021-11-30
category: Writeup
image: assets/img/blog/csr.png
author: Lukas Marckmiller
tags: ctf
---

# FlagCheckerBaby
 
This was a pretty basic reverse challenge. We got provided the source code `chall.c` and a binary `chall`. 
``` c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void check(const char *input, const char *secret_flag) {	
	char guess[32], flag[64];
	if (strlen(input) > sizeof(guess)) {
		puts("HACKER!");
		return;
	}

	strncpy(guess, input, sizeof(guess));
	strncpy(flag, secret_flag, sizeof(flag));
	if (!strcmp(guess, flag)) {
		printf("Well done! You got it: %s\n", flag);
	}
	else {
		printf("Wrong flag: %s\n", guess);
	}
}

int main(int argc, char** argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	char *secret_flag = getenv("FLAG");
	if (!secret_flag) {
		puts("Flag not found, contact challenge authors.");
		return 1;
	}

	char input[128];
	printf("Enter the flag: ");
	fgets(input, sizeof(input), stdin);
	check(input, secret_flag);

	return 0;
}
```
After checking for basic things like *buffer overflow* and *format string* attacks on common c functions I came across the following line:
`strncpy(guess, input, sizeof(guess));`
<br> In the [official documentation](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-strncpy-l-wcsncpy-wcsncpy-l-mbsncpy-mbsncpy-l?view=msvc-170) of the function *strncpy* we can observe a weird behavior of the function that is also marked as a potential security weakness. 
> The strncpy function copies the initial count characters of strSource to strDest and returns strDest. If count is less than or equal to the length of strSource, a null character (terminating string) is not appended automatically to the copied string. If count is greater than the length of strSource, the destination string is padded with null characters up to length count.

Since the code checks for the boundaries are insufficient, see: `if (strlen(input) > sizeof(guess)) {` We can provide an input string that is the same size as *guess* and doesn't contain a trailing character. Now we need a function that prints out the guess variable by printing it out until it finds a null character. That would be following line: `printf("Wrong flag: %s\n", guess);`. Since the *guess* doesn't contain a terminating null character the function reads over the boundaries of *guess* and we get provided with the flag.<br>
[Here](https://devblogs.microsoft.com/oldnewthing/20050107-00/?p=36773) an article that sums up the attack pretty good: 

