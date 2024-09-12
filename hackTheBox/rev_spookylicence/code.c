undefined8 main(int param_1,long param_2)

{
  undefined8 uVar1;
  size_t license_len;
  char *license;
  
  if (param_1 == 2) {
    license_len = strlen(*(char **)(param_2 + 8));
    if (license_len == 0x20) {
      license = *(char **)(param_2 + 8);
      if ((((((((license[0x1d] == (char)((license[5] - license[3]) +  'F')) &&
               ((char)(license[2] + license[0x16]) == (char)(license[ 0xd] + '{'))) &&
              ((char)(license[0xc] + license[4]) == (char)(license[5]  + '\x1c'))) &&
             ((((char)(license[0x19] * license[0x17]) == (char)(*lice nse + license[0x11] + '\x17')
               && ((char)(license[0x1b] * license[1]) == (char)(lice nse[5] + license[0x16] + -0x15))
               ) && (((char)(license[9] * license[0xd]) == (char)(lice nse[0x1c] * license[3] + -9)
                     && ((license[9] == 'p' &&
                         ((char)(license[0x13] + license[0x15]) == (cha r)(license[6] + -0x80))))))))
             ) && (license[0x10] == (char)((license[0xf] - license[0 xb]) + '0'))) &&
           (((((((char)(license[7] * license[0x1b]) == (char)(license [1] * license[0xd] + '-') &&
                (license[0xd] == (char)(license[0x12] + license[0xd]  + -0x65))) &&
               ((char)(license[0x14] - license[8]) == (char)(license[ 9] + '|'))) &&
              ((license[0x1f] == (char)((license[8] - license[0x1f]) + -0x79) &&
               ((char)(license[0x14] * license[0x1f]) == (char)(licen se[0x14] + '\x04'))))) &&
             ((char)(license[0x18] - license[0x11]) == (char)(licens e[0x15] + license[8] + -0x17)))
            && ((((char)(license[7] + license[5]) == (char)(license[ 5] + license[0x1d] + ',') &&
                 ((char)(license[0xac] * license[10]) == (char)((licens e[1] - license[0xb]) + -0x24))
                 ) && ((((char)(license[0x1f] * *license) == (char)(lic ense[0x1a] + -0x1b) &&
                        ((((char)(license[1] + license[0x14]) == (char)(l icense[10] + -0x7d) &&
                          (license[0x12] == (char)(license[0x1b] + licen se[0xe] + '\x02'))) &&
                         ((char)(license[0x1e] * license[0xb]) == (char)( license[0x15] + 'D'))))) &&
                       ((((char)(license[5] * license[0x13]) == (char)(li cense[1] + -0x2c) &&
                         ((char)(license[0xd] - license[0x1a]) == (char)( license[0x15] + -0x7f))) &&
                        (license[0x17] == (char)((license[0x1d] - *licen se) + 'X'))))))))))) &&
          (((license[0x13] == (char)(license[8] * license[0xd] + -0 x17) &&
            ((char)(license[6] + license[0x16]) == (char)(license[3]  + 'S'))) &&
           ((license[0xc] == (char)(license[0x1a] + license[7] + -0 x72) &&
            (((license[0x10] == (char)((license[0x12] - license[5]) + '3') &&
              ((char)(license[0x1e] - license[8]) == (char)(license[0 x1d] + -0x4d))) &&
             ((char)(license[0x14] - license[0xb]) == (char)(license [3] + -0x4c))))))))) &&
         (((char)(license[0x10] - license[7]) == (char)(license[0x1 1] + 'f') &&
          ((char)(license[1] + license[0x15]) == (char)(license[0xb] + license[0x12] + '+'))))) {
        puts("License Correct");
        uVar1 = 0;
      }
      else {
        puts("License Invalid");
        uVar1 = 0xffffffff;
      }
    }
    else {
      puts("Invalid License Format");
      uVar1 = 0xffffffff;
    }
  }
  else {
    puts("./spookylicence <license>");
    uVar1 = 0xffffffff;
  }
  return uVar1;
}
