#include <stdio.h>
#include <feistalBox/feistalBox.h>
#include <Aisinossl/sm4/sm4.h>
#include <Aisinossl/sm4_whitebox/sm4_whitebox.h>
#include <Aisinossl/sm4_whitebox/sm4_whitebox_generator.h>
#include <wbc2/wbc2.h>

void dump(const uint8_t * li, int len) {
    int line_ctrl = 16;
    for (int i=0; i<len; i++) {
        printf("%02X", (*li++));
        if ((i+1)%line_ctrl==0) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
}

size_t cal_box_size(FeistalBox fb){
    return sizeof(FeistalBox) - 2 * sizeof(unsigned char*) + fb.tableSize + fb.pSize;
}

#include "count_cycles.h"

unsigned long getFileSize(FILE* f){
    if(f == NULL)
        return 0;
    unsigned long res;
    fseek(f , 0 ,SEEK_END);
    res = ftell(f);
    rewind(f);
    return res;
}


int wbc2WithAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    // const uint8_t key[16] = { 0 };
    printf("With Affine: %d rounds\n", rounds);
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;

    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    printf("enc table size: %d\tp size: %d\n", fb_enc.tableSize, fb_enc.pSize);
    printf("dec table size: %d\tp size: %d\n", fb_dec.tableSize, fb_dec.pSize);

    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    // dump(ip, 16);
    set_time_start();
    ret = feistalRoundEnc(&fb_enc, ip, op);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = feistalRoundDec(&fb_dec, op, buf);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 16);
    printf("DecText ?= Plaintext:\t%s\n", ret==0?"√":"✘");
    if (ret != 0){
        dump(ip,16);
        dump(op,16);
        dump(buf, 16);
    }
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    free(buf);
    free(op);
    return 0;
}

int wbc2NoAffine(const uint8_t key[16], const uint8_t ip[16], int rounds)
{
    printf("No Affine: %d rounds\n", rounds);
    // const uint8_t key[16] = { 0 };
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;

    set_time_start();
    ret = initFeistalBoxConfigNoAffine(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfigNoAffine Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    // dump(fb.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t*) malloc(16);
    op = (uint8_t*) malloc(16);
    // dump(ip, 16);
    set_time_start();
    ret = feistalRoundEnc(&fb_enc, ip, op);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = feistalRoundDec(&fb_dec, op, buf);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 16);
    printf("DecText ?= Plaintext:\t%s\n", ret==0?"√":"✘");
    if (ret != 0){
        dump(ip,16);
        dump(op,16);
        dump(buf, 16);
    }
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    free(buf);
    free(op);
    return 0;
}

int wbc2_example()
{
    const uint8_t key[16] = { 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    const uint8_t ip[16] = { 0x01,0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
//    int rounds = 10;
    wbc2NoAffine(key, ip, 5);
    wbc2NoAffine(key, ip, 50);
    wbc2NoAffine(key, ip, 500);
    printf("\n");
    wbc2WithAffine(key, ip, 5);
    wbc2WithAffine(key, ip, 50);
    wbc2WithAffine(key, ip, 500);
    printf("\n");
    return 0;
}

int import_test()
{
    const uint8_t key[16] = "0000000000000000";
    const uint8_t ip[16] = {0};
    int rounds = 10;
    printf("With Affine: %d rounds\n", rounds);
    FeistalBox fb_enc, fb_dec;
    FeistalBoxConfig cfg;
    int ret;
    size_t size1 = 0;
    size_t size2 = 0;

    set_time_start();
    ret = initFeistalBoxConfigNoAffine(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    unsigned char* buf1 = FEISTALBOX_export_to_str(&fb_enc, &size1);
    unsigned char* buf2 = FEISTALBOX_export_to_str(&fb_dec, &size2);
    void* box1 = FEISTALBOX_import_from_str(buf1);
    void* box2 = FEISTALBOX_import_from_str(buf2);
    printf("Buf1 size:%ld\nBuf2 size:%ld\n", size1, size2);


    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t *)malloc(16);
    op = (uint8_t *)malloc(16);
    // dump(ip, 16);
    set_time_start();
    ret = feistalRoundEnc(box1, ip, op);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = feistalRoundDec(box2, op, buf);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 16);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    dump(ip, 16);
    dump(op, 16);
    dump(buf, 16);
    // dump(buf, 16);
    FILE* f1;
    FILE* f2;
    f1 = fopen("enc_table","wb");
    f2 = fopen("dec_table","wb");
    fwrite(buf1, sizeof(unsigned char), size1, f1);
    fwrite(buf2, sizeof(unsigned char), size2, f2);
    fclose(f1);
    fclose(f2);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    releaseFeistalBox(box1);
    releaseFeistalBox(box2);
    free(buf1);
    free(buf2);
    return 0;
}

int wcfb_example(){
    int rounds = 100;
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    //const uint8_t ip[33] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE};
    unsigned char ip[1024];
    memset(ip, 0xff, 1024);
    unsigned char iv[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    FeistalBoxConfig cfg;
    FeistalBox fb_enc, fb_dec;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);



    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t *)malloc(1024);
    op = (uint8_t *)malloc(1040);
    int num = 0;
    // dump(ip, 16);
    set_time_start();
    ret = FEISTALBOX_wcfb_encrypt(ip, op, 1024, &fb_enc, &num, iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    num = 0;
    // dump(op, 16);
    set_time_start();
    ret = FEISTALBOX_wcfb_encrypt(op, buf, 1040, &fb_dec, &num, iv, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 1024);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    printf("\ninput:\n");
    dump(ip, 33);
    printf("\noutput:\n");
    dump(op, 49);
    printf("\nafter decode:\n");
    dump(buf, 33);
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int cbc_cfb_example(){
    int rounds = 10;
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    const uint8_t ip[32] = { 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEE};
    unsigned char iv[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    unsigned char iv2[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    FeistalBoxConfig cfg;
    FeistalBox fb_enc, fb_dec;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);



    // dump(fb_enc.table, len);
    //uint8_t *op, *buf;
    //buf = (uint8_t *)malloc(32);
    //op = (uint8_t *)malloc(32);
    uint8_t op[32];
    uint8_t buf[32];
    int num = 0;
    // dump(ip, 16);
    set_time_start();
    ret = FEISTALBOX_cfb_encrypt(ip, op, 32, &fb_enc, &num,iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();

    ret = FEISTALBOX_cfb_encrypt(op, buf, 32, &fb_enc, &num,iv2, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(buf, ip, 32);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    printf("\ninput:\n");
    dump(ip, 32);
    printf("\noutput:\n");
    dump(op, 32);
    printf("\nafter decode:\n");
    dump(buf, 32);
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int wcbc_example(){
    int rounds = 10;
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    unsigned char ip[1024];
    unsigned char iv[16] = {0x11, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0xde, 0xf0, 0x12, 0x37, 0x56, 0x75, 0x94, 0xb3, 0xd2, 0xf1};
    memset(ip, 0xff, 1024);
    FeistalBoxConfig cfg;
    FeistalBox fb_enc, fb_dec;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, &fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, &fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);



    // dump(fb_enc.table, len);
    uint8_t *op, *buf;
    buf = (uint8_t *)malloc(1024);
    op = (uint8_t *)malloc(1056);
    // dump(ip, 16);
    set_time_start();
    ret = FEISTALBOX_wcbc_encrypt(ip, op, 1024, &fb_enc, iv, FEISTALBOX_ENC, WRAP_LEN);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = FEISTALBOX_wcbc_encrypt(op, buf, 1056, &fb_dec, iv, FEISTALBOX_DEC,WRAP_LEN);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(ip, buf, 1024);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    // dump(buf, 16);
    releaseFeistalBox(&fb_enc);
    releaseFeistalBox(&fb_dec);
    return 0;
}

int wcbc_test(FeistalBox* fb_enc, FeistalBox* fb_dec, const unsigned char* ip, size_t size){
    unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t padding_length  = (size % 16 == 0)? size : size + 16 - (size % 16) ;
    unsigned char* op = malloc(size + 16*3);
    unsigned char* buf = malloc(padding_length + 16);
    int ret;
    
    set_time_start();
    ret = FEISTALBOX_wcbc_encrypt(ip, op, size, fb_enc, iv, FEISTALBOX_ENC, WRAP_LEN);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = FEISTALBOX_wcbc_encrypt(op, buf, ret, fb_dec, iv2, FEISTALBOX_DEC,WRAP_LEN);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(ip, buf, size);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    free(op);
    free(buf);
    return 0;
}

int cbc_test(FeistalBox* fb_enc, FeistalBox* fb_dec, const unsigned char* ip, size_t size){
    unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t padding_length  = (size % 16 == 0)? size : size + 16 - (size % 16) ;
    unsigned char* op = malloc(padding_length );
    unsigned char* buf = malloc(padding_length );
    int ret;
    
    set_time_start();
    ret = FEISTALBOX_cbc_encrypt(ip, op, size , fb_enc, iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    set_time_start();
    ret = FEISTALBOX_cbc_encrypt(op, buf, size , fb_dec, iv2, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(ip, buf, size);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    free(op);
    free(buf);
    return 0;
}

int wcfb_test(FeistalBox* fb_enc, FeistalBox* fb_dec, const unsigned char* ip, size_t size){
    unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char* op = malloc(size + 16*3);
    unsigned char* buf = malloc(size);
    int ret;
    int num=0;
    
    set_time_start();
    ret = FEISTALBOX_wcfb_encrypt(ip, op, size, fb_enc, &num, iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    num = 0;
    set_time_start();
    ret = FEISTALBOX_wcfb_encrypt(op, buf, ret, fb_dec, &num, iv2, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(ip, buf, size);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    free(op);
    free(buf);
    return 0;
}

int cfb_test(FeistalBox* fb_enc, FeistalBox* fb_dec, const unsigned char* ip, size_t size){
    unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char* op = malloc(size );
    unsigned char* buf = malloc(size);
    int ret;
    int num=0;
    
    set_time_start();
    ret = FEISTALBOX_cfb_encrypt(ip, op, size, fb_enc, &num, iv, FEISTALBOX_ENC);
    set_time_ends();
    printf("Enc FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    // dump(op, 16);
    num = 0;
    set_time_start();
    ret = FEISTALBOX_cfb_encrypt(op, buf, ret, fb_enc, &num, iv2, FEISTALBOX_DEC);
    set_time_ends();
    printf("Dec FeistalBox Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    ret = memcmp(ip, buf, size);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");
    free(op);
    free(buf);
    return 0;
}

int feitsalBox_test(char filename[], FeistalBox* fb_enc, FeistalBox* fb_dec,int rounds){
    FILE* f;
    unsigned char* buf;
    unsigned long file_size;
    f = fopen(filename,"rb");
    file_size = getFileSize(f);
    double sizeInMB = (double)file_size / 1024.0 / 1024.0;
    buf = malloc(file_size);
    fread(buf, sizeof(unsigned char), file_size, f);
    printf("\n\nFeistalBox Test:\n");
    printf("Filename:%s , file size:%.2lfMB , rounds:%d\n", filename,sizeInMB,rounds);
    
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
//    unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    
     printf("\n\nwcbc_test:\n");
     wcbc_test(fb_enc, fb_dec, buf, file_size);
     
     printf("\n\nwcfb_test:\n");
     wcfb_test(fb_enc, fb_dec, buf, file_size);
    
    
    printf("\n\ncbc_test:\n");
    cbc_test(fb_enc, fb_dec, buf, file_size);
    
    printf("\n\ncfb_test:\n");
    cfb_test(fb_enc, fb_dec, buf, file_size);
    
    free(buf);
    return 0;
}

int  genBox_test(FeistalBox *fb_enc ,FeistalBox *fb_dec, int rounds){
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    FeistalBoxConfig cfg;
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    printf("\nRounds:%d\n",rounds);
    set_time_start();
    ret = initFeistalBoxConfig(FeistalBox_SM4_128_128, key, 1, 15, rounds, &cfg);
    set_time_ends();
    printf("initFeistalBoxConfig Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeEnc, fb_enc);
    set_time_ends();
    printf("generate Enc FeistalBox Spent: %f s, %lld cycles ,Box Size:%lld , Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), cal_box_size(*fb_enc), ret);
    
    set_time_start();
    ret = generateFeistalBox(&cfg, eFeistalBoxModeDec, fb_dec);
    set_time_ends();
    printf("generate Dec FeistalBox Spent: %f s, %lld cycles ,Box Siez:%lld, Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), cal_box_size(*fb_dec), ret);

    return 0;
}

void test_suite(){
    int i;
    //1MB
    char filename_0[] = "E:\\whiteBox\\WhiteboxCipher2\\build\\test0";
    //10MB
    char filename_1[] = "test1";
    //100MB
    char filename_2[] = "test2";
    //1024MB
    char filename_3[] = "test3";

    FeistalBoxConfig cfg[5];
    FeistalBox enc_box[5];
    FeistalBox dec_box[5];
    for(i = 0;i < 5;i++){
        genBox_test(&enc_box[i], &dec_box[i], (i + 1) * 100);
    }
    for(i = 0;i < 5;i++){
        feitsalBox_test(filename_0, &enc_box[i], &dec_box[i], (i + 1)* 100);
    }
    /*
    for(i = 0;i < 5;i++){
        feitsalBox_test(filename_1, &enc_box[i], &dec_box[i], (i + 1)* 100);
    }
    for(i = 0;i < 5;i++){
        feitsalBox_test(filename_2, &enc_box[i], &dec_box[i], (i + 1)* 100);
    }
    for(i = 0;i < 5;i++){
        feitsalBox_test(filename_3, &enc_box[i], &dec_box[i], (i + 1)* 100);
    }
    */
}

/*
int sm4_test(char filename[]){
    FILE* f;
    unsigned char* buf;
    unsigned char* op;
    unsigned char* output_buf;
    size_t file_size;
    sm4_key_t enc_key,dec_key;
    int num;
    f = fopen(filename,"rb");
    file_size = getFileSize(f);
    double sizeInMB = (double)file_size / 1024.0 / 1024.0;
    buf = malloc(file_size);
    output_buf = malloc(file_size);
    op = malloc(file_size);
    fread(buf, sizeof(unsigned char), file_size, f);
    printf("\n\nSM4 Test:\n");
    printf("Filename:%s , file size:%.2lfMB\n",filename, sizeInMB);
    int ret;
    
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};

    unsigned char iv0[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char iv3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    set_time_start();
    sm4_set_encrypt_key(&enc_key, key);
    sm4_set_decrypt_key(&dec_key, key);
    set_time_ends();
    printf("init sm4 Spent: %f s, %lld cycles \n", get_clock_elapsed(), get_cycles_elapsed());
    
    set_time_start();
    sm4_cbc_encrypt(buf, output_buf,file_size, &enc_key, iv0, SM4_ENCRYPT);
    set_time_ends();
    printf("SM4 CBC encrypt Spent: %f s, %lld cycles \n", get_clock_elapsed(), get_cycles_elapsed());


    set_time_start();
    sm4_cbc_encrypt(output_buf, op,file_size, &dec_key, iv1, SM4_DECRYPT);
    set_time_ends();
    printf("SM4 CBC decrypt Spent: %f s, %lld cycles \n", get_clock_elapsed(), get_cycles_elapsed());

    ret = memcmp(buf, op, file_size);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");

    //memset(output_buf, 0 ,file_size);
    //memset(op, 0 ,file_size);

    set_time_start();
    sm4_cfb128_encrypt(buf, output_buf,file_size, &enc_key, iv2, &num, SM4_ENCRYPT);
    set_time_ends();
    printf("SM4 CFB encrypt Spent: %f s, %lld cycles \n", get_clock_elapsed(), get_cycles_elapsed());
    
    num = 0;

    set_time_start();
    sm4_cfb128_encrypt(output_buf, op, file_size, &enc_key, iv3, &num, SM4_DECRYPT);
    set_time_ends();
    printf("SM4 CFB decrypt Spent: %f s, %lld cycles \n", get_clock_elapsed(), get_cycles_elapsed());

    ret = memcmp(buf, op, file_size);
    printf("DecText ?= Plaintext:\t%s\n", ret == 0 ? "OK" : "NO");

    free(buf);
    return 0;
}
*/
/*
int sm4WhiteBox_test(char filename[]){
    FILE* f;
    unsigned char* buf;
    unsigned char* output_buf;
    size_t file_size;
    Sm4Whitebox enc_table,dec_table;
    f = fopen(filename,"rb");
    file_size = getFileSize(f);
    double sizeInMB = (double)file_size / 1024.0 / 1024.0;
    buf = malloc(file_size);
    output_buf = malloc(file_size);
    fread(buf, sizeof(unsigned char), file_size, f);
    printf("SM4 Test:\n");
    printf("Filename:%s , file size:%.2lf\n", sizeInMB);
    
    int ret;
    const uint8_t key[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    unsigned char iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //initFeistalBox(FeistalBox_SM4_128_128, &fb);
    set_time_start();
    sm4_wb_gen_tables(key, &enc_table, SM4_ENCRYPT);
    set_time_ends();
    printf("init sm4 whitebox encrypt box Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    set_time_start();
    sm4_wb_gen_tables(key, &dec_table, SM4_DECRYPT);
    set_time_ends();
    printf("init sm4 whitebox encrypt box Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);
    
    set_time_start();
    sm4_wb_cbc_encrypt(buf, output_buf,file_size, &enc_table, iv);
    set_time_ends();
    printf("SM4 WhiteBox CBC encrypt Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    memset(output_buf, 0 ,file_size);

    set_time_start();
    sm4_wb_cbc_decrypt(buf, output_buf,file_size, &dec_table, iv);
    set_time_ends();
    printf("SM4 WhiteBox CBC decrypt Spent: %f s, %lld cycles Ret: %d\n", get_clock_elapsed(), get_cycles_elapsed(), ret);

    memset(output_buf, 0 ,file_size);


    free(buf);
    return 0;
}
*/

int main(int argv, char **argc)
{
    test_suite();
    //Test for 1MB file
    //sm4_test(filename_0);
    //sm4WhiteBox_test(filename_0);

}
