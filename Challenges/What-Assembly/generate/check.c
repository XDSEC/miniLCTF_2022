#include <stdio.h>
#include <string.h>
#include <malloc.h>

#define ROL(a,b) (((a) << (b)) | ((a) >> (8 - (b))))
#define u8 unsigned char

void qua_rou(u8 *s, int a, int b, int c, int d) {
  s[b] ^= ROL((s[a] + s[d]) & 0xff, 4);
  s[d] ^= ROL((s[c] + s[b]) & 0xff, 2);
  s[c] ^= ROL((s[b] + s[a]) & 0xff, 3);
  s[a] ^= ROL((s[d] + s[c]) & 0xff, 1);
}

int check(const char* cflag, const char* key, const char* enc) {
    const char table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    int flaglen = strlen(cflag);
    int keylen = strlen(key);
    int enclen = strlen(enc);
    if (keylen < 8)
        return -1;
    if ((flaglen * 4 <= enclen - 32) || (flaglen * 4 > enclen))
        return -1;

    int padlen = (flaglen + 15) & ~15;
    char *flag = (char*)malloc(padlen);
    memset(flag, 0, padlen);
    memcpy(flag, cflag, flaglen);

    u8 s[16];
    for (int i = 0; i < 8; i++)
        s[i] = key[i];

    int correct = 0;
    for (int i = 0; i < flaglen; i += 8) {
        for (int j = 0; j < 8; j++)
            s[8 + j] = flag[i + j];

        for (int j = 0; j < 42; j++) {
            qua_rou(s, 12, 8, 4, 0);
            qua_rou(s, 13, 9, 5, 1);
            qua_rou(s, 14, 10, 6, 2);
            qua_rou(s, 15, 11, 7, 3);
            qua_rou(s, 15, 10, 5, 0);
            qua_rou(s, 12, 11, 6, 1);
            qua_rou(s, 13, 8, 7, 2);
            qua_rou(s, 14, 9, 4, 3);
        }
        for (int j = 0; j < 16; j++) {
            correct |= (enc[i * 4 + j * 2 + 0] != table[s[j] / 0x10]);
            correct |= (enc[i * 4 + j * 2 + 1] != table[s[j] % 0x10]);
        }
    }
    free(flag);
    return correct;
}

int main() {
    printf("%d\n", check("miniLctf{0ooo00oh!h3ll0_WASM_h4ck3r!}", "D33.B4T0", "05779c24d9249e693fa7ac4a10c68dfbd3520083b33f56e90fd84978b6a15c970b976779a8fefe91fb87d2221c9a1f87ed7eaddb8ae6370f9de69e3a7a5c5c488cde79756b0b9f1713e749edd41cff04"));
    return 0;
}