# ARMs Race

## Solution

Once connected through netcat you can notice that the program is printing a string of hex characters. Since the name of the challenge is "ARM"s race, my guess is that the hex string is actually ARM code. So to confirm this I used the following command to convert the hex string to binary and then disassemble it using `arm-none-eabi-objdump`.

```bash
echo "370301e3861506e305134fe3752603e3182b44e3010040e00200c0e0971e0ee388114fe3fa2a08e3c32347e3010080e00200a0e02c160ce3061446e3ea2308e36c2c4fe3010080e1020080e1ec1703e3781045e3cf2905e37a204be3010080e00200a0e0c61006e3eb184ae3c02204e3052a4be3010040e00200c0e04f1001e3781940e31c2a05e35b2d43e3010040e00200c0e03b1f07e3d61e4ce3b72202e34d2f44e3010040e00200c0e0c61d08e382164be31c2107e32d274ae3900100e0900200e0d81c03e3ed1b47e35f2508e3752d46e3010020e0020020e083160be3241946e3c02e09e34d2f4fe3010000e0020000e08b1c0de39c1349e37b2501e3e42349e3900100e0900200e0121b0ee392144ce32c2009e3e72042e3010020e0020020e0a8170ae3701a40e32a2108e3d72b41e3010040e00200c0e02d1506e36b164ee3a72d0fe3b22d46e3010080e00200a0e0381901e30a1c4be3602b0ee3642042e3010000e0020000e0e9110fe3171540e3992906e3c12547e3900100e0900200e09a1b00e3ae1642e3e8200ee34c214fe3900100e0900200e0f8160fe3cb184ce3422503e3132e4ce3900100e0900200e0261609e3191541e3892c06e3a32844e3900100e0900200e0b91204e3441c48e3542902e3df2340e3010080e00200a0e0" > hexdata.txt

xxd -r -p hexdata.txt binaryfile.bin

arm-none-eabi-objdump -D -b binary -m arm binaryfile.bin
```

If you run the above commands you will see that the hex string is actually ARM code. So now I need a way to calculate the value of the `r0` register at the end of the program. By looking on Google and with my friend ChatGPT I found out that by using Unicorn [1] I can emulate the ARM code through Python and get the value of `r0`. Then it is just a matter of iterating the same process 50 times to retrieve the flag. 

You can find the Python script at [solution.py](./sol.py).

# Sources

- [1] Unicorn Engine: [https://www.unicorn-engine.org/](https://www.unicorn-engine.org/)