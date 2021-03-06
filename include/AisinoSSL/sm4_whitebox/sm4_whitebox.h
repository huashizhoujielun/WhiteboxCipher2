/*
 * @Author: Weijie Li 
 * @Date: 2017-11-06 22:04:17 
 * @Last Modified by: Weijie Li
 * @Last Modified time: 2017-12-27 10:39:04
 */


#ifndef  AISINOSSL_SM4_WHITEBOX_H_
#define  AISINOSSL_SM4_WHITEBOX_H_

#include <stdint.h>
#include <AisinoSSL/sm4_whitebox/sm4_whitebox_config.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SM4_WHITEBOX_F

#include <AisinoSSL/sm4/sm4.h>
#include <AisinoSSL/math/affine_transform.h>

#define SM4_ENCRYPT 1
#define SM4_DECRYPT 0

typedef GCM128_CONTEXT SM4_WB_GCM128_CONTEXT;

typedef struct sm4_wb_t{
    uint32_t rounds;

    uint32_t    ssbox_enc[SM4_WHITEBOX_ROUND_MAX][4][256];
    AffineTransform M[SM4_WHITEBOX_ROUND_MAX][3];
    AffineTransform C[SM4_WHITEBOX_ROUND_MAX];
    AffineTransform D[SM4_WHITEBOX_ROUND_MAX];
    
    // start encoding
    AffineTransform SE[4];
    AffineTransform FE[4];
    
    #if SM4_WHITEBOX_DEBUG_INFO_F
    //debug to be del
        AffineTransform P[SM4_WHITEBOX_NUM_STATES][2];
    #endif /*  SM4_WHITEBOX_DEBUG_INFO_F */       

} Sm4Whitebox;

/**
 * @brief sm4 whitebox encrypto function  
 * 
 * @param in both plaintext and ciphertext are ok, only accept one block: 16 uint8_t 
 * @param out the text that processed by sm4_wb_ctx 
 * @param sm4_wb_ctx sm4_whitebox ctx, generated by int sm4_wb_gen_tables(const uint8_t *key, Sm4Whitebox *sm4_wb_ctx, int enc) or int sm4_wb_gen_tables_with_dummyrounds(const uint8_t *key, Sm4Whitebox *sm4_wb_ctx, int enc, int dummyrounds);
 */
void sm4_wb_enc(const uint8_t *in, uint8_t *out, Sm4Whitebox *sm4_wb_ctx);

#define sm4_wb_encrypt(in,out,sm4_wb_ctx) sm4_wb_enc(in, out, sm4_wb_ctx);
#define sm4_wb_decrypt(in,out,sm4_wb_ctx)  sm4_wb_encrypt(in,out,sm4_wb_ctx)


/**
 * @brief free the space of sm4_wb_ctx
 * 
 * @param sm4_wb_ctx 
 * @return int 0 is successful, otherwise fault
 */
int sm4_wb_free(Sm4Whitebox *sm4_wb_ctx);

/**
 * @brief sm4 whitebox encrypto function using CTR mode
 * 
 * @param in input 
 * @param out output
 * @param len length of data in bytes
 * @param key sm4_whitebox_ctx
 * @param iv iv
 * @param ecount_buf extra state, must be initialised with zeros before the first call
 * @param num extra state, must be initialised with zeros before the first call
 * @return int 0 is successful, otherwise fault 
 */
int sm4_wb_ctr_encrypt(const uint8_t *in, uint8_t *out, 
                    size_t len, const Sm4Whitebox * key, unsigned char *iv,
                    unsigned char ecount_buf[SM4_BLOCK_SIZE], unsigned int *num);

/**
 sm4_wb_cbc_encrypt

 @param in in
 @param out out
 @param len byte size of in
 @param ctx key sm4_whitebox_ctx
 @param iv iv
 */
void sm4_wb_cbc_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, const Sm4Whitebox * ctx, unsigned char *iv);

/**
 sm4_wb_cbc_decrypt

 @param in in
 @param out out
 @param len byte size of in
 @param ctx key sm4_whitebox_ctx
 @param iv iv
 */
void sm4_wb_cbc_decrypt(const unsigned char *in, unsigned char *out,
	size_t len, const Sm4Whitebox * ctx, unsigned char *iv);

/**
 sm4_wb_gcm128_init

 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 @param wb_ctx Sm4Whitebox
 */
void sm4_wb_gcm128_init(SM4_WB_GCM128_CONTEXT *gcm_ctx, Sm4Whitebox *wb_ctx);

/**
 sm4_wb_gcm128_setiv

 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 @param ivec iv
 @param len byte size of iv
 */
void sm4_wb_gcm128_setiv(SM4_WB_GCM128_CONTEXT *gcm_ctx, const unsigned char *ivec,
                      size_t len);

/**
 addition message of gcm

 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 @param aad addition message
 @param len byte size of aad
 @return 1 to successful, otherwises fault
 */
int sm4_wb_gcm128_aad(SM4_WB_GCM128_CONTEXT *gcm_ctx, const unsigned char *aad,
                    size_t len);

/**
 sm4_wb_gcm128_encrypt

 @param in in
 @param out out
 @param length byte size of in
 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 @param enc 1 to SM4_ENCRYPT, 0 to SM4_DECRYPT
 @return 1 to successful, otherwises fault
 */
int sm4_wb_gcm128_encrypt(const unsigned char *in, unsigned char *out,
                        size_t length, SM4_WB_GCM128_CONTEXT *gcm_ctx, const int enc);

/**
 get tag of sm4_wb_gcm128

 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 @param tag memory for storage tag
 @param len byte size of tag
 */
void sm4_wb_gcm128_tag(SM4_WB_GCM128_CONTEXT *gcm_ctx, unsigned char *tag,
                    size_t len);

/**
 sm4_wb_gcm128_finish

 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 @param tag memory for storage tag
 @param len byte size of tag
 @return 1 to successful, otherwises fault
 */
int sm4_wb_gcm128_finish(SM4_WB_GCM128_CONTEXT *gcm_ctx, const unsigned char *tag,
                      size_t len);

/**
 release SM4_WB_GCM128_CONTEXT

 @param gcm_ctx SM4_WB_GCM128_CONTEXT
 */
void sm4_wb_gcm128_release(SM4_WB_GCM128_CONTEXT *gcm_ctx);



/**
 * sm4 gcm file context
 */
typedef gcmf_context sm4_wb_gcmf_context;

/**
 * init the sm4 gcm file context
 *
 * @param  ctx [in]		gcm file context
 * 
 * @param  sm4_key [in]		sm4 key
 *
 * @return     [flag]		if successful o,otherwise failed
 */
int sm4_wb_gcmf_init(sm4_wb_gcmf_context *ctx, const Sm4Whitebox *wb_ctx);

/**
 * gcm file context free
 *
 * @param  ctx [in]		gcm file context
 *
 * @return     [flag]		if successful o,otherwise failed
 */
int sm4_wb_gcmf_free(sm4_wb_gcmf_context *ctx);

/**
 * set sm4 iv param
 *
 * @param  ctx [in]		gcm file context
 *
 * @param  iv  [iv]		iv array
 *
 * @param  len [in]		iv array length
 *
 * @return     [flag]		if successful o,otherwise failed
 */
int sm4_wb_gcmf_set_iv(sm4_wb_gcmf_context *ctx, const unsigned char * iv, size_t len);


/**
 * encrypte file
 *
 * @param  ctx      [in]		gcm file context
 *
 * @param  infpath  [in]		plaintext file input path
 *
 * @param  outfpath [in]		cipher file output path
 *
 * @return          [fage]		if successful o,otherwise failed
 */
int sm4_wb_gcmf_encrypt_file(sm4_wb_gcmf_context * ctx, char *infpath, char *outfpath);


/**
 * decrypt file
 *
 * @param  ctx      [in]		gcm file context
 *
 * @param  infpath  [in]		cipher file input path
 *
 * @param  outfpath [in]		plaintext file output path
 *
 * @return          [flag]		if successful o,otherwise failed
 */
int sm4_wb_gcmf_decrypt_file(sm4_wb_gcmf_context * ctx, char *infpath, char *outfpath);

/**
 * @brief export Sm4Whitebox to byte
 * 
 * @param ctx a pointer of Sm4Whitebox
 * @param dest a pointer to a pointer of byte[]
 * @return int byte[] size
 */
int sm4_wb_export_to_str(const Sm4Whitebox* ctx, void **dest) ;

/**
 * @brief import Sm4Whitebox from str
 * 
 * @param source 
 * @return Sm4Whitebox* 
 */
Sm4Whitebox*  sm4_wb_import_from_str(const void *source);

#endif /* SM4_WHITEBOX_F */

#ifdef __cplusplus
}
#endif
#endif //AISINOSSL_SM4_WHITEBOX_H_