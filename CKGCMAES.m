//
// CryptoKit
//
// The MIT License (MIT)
//
// Copyright (c) 2014 Mehrdad Afshari
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//


#import "CKGCMAES.h"

#import <Security/SecRandom.h>
#import <openssl/evp.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define AES_KEY_LEN 16

@implementation CKGCMAES

+ (NSUInteger)keyLength
{
	return AES_KEY_LEN;
}

+ (CKSensitiveBuffer *)decrypt:(id<CKData>)message key:(id<CKData>)key
{
	if (message.length == 0) return nil;
	if (!key) return nil;
	if (key.length < AES_KEY_LEN) return nil;
	if (message.length <= GCM_IV_LEN + GCM_TAG_LEN) return nil;
	
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	
	const uint8_t *const iv = message.bytes;
	const uint8_t *const tag = iv + GCM_IV_LEN;
	const uint8_t *ctxt = tag + GCM_TAG_LEN;
	size_t clen = message.length - GCM_TAG_LEN - GCM_IV_LEN;
	
	if (!EVP_DecryptInit_ex(&ctx, EVP_aes_128_gcm(), NULL, key.bytes, iv)) return nil;
	
	uint8_t *const decryptedData = malloc(clen);
	uint8_t *ptxt = decryptedData;
	if (!ptxt) return nil;

	int len;

	while (clen > UINT32_MAX) {
		if (!EVP_DecryptUpdate(&ctx, ptxt, &len, ctxt, UINT32_MAX)) goto error;
		
		ptxt += len;
		ctxt += UINT32_MAX;
		clen -= UINT32_MAX;
	}
	
	if (clen) {
		if (!EVP_DecryptUpdate(&ctx, ptxt, &len, ctxt, (uint32_t)clen)) goto error;
		ptxt += len;
	}

	if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag)) goto error;

	if (EVP_DecryptFinal_ex(&ctx, ptxt, &len) <= 0) goto error;
	ptxt += len;

	EVP_CIPHER_CTX_cleanup(&ctx);
	
	return [CKSensitiveBuffer bufferWithBytes:decryptedData length:ptxt - decryptedData];
error:
	free(decryptedData);
	return nil;
}

+ (NSData *)encrypt:(id<CKData>)message key:(id<CKData>)key
{
	if (message.length == 0) return nil;
	assert(key.length >= AES_KEY_LEN);

	const size_t outputBufferLen = GCM_IV_LEN + GCM_TAG_LEN + message.length + EVP_MAX_BLOCK_LENGTH;
	uint8_t *const outputBuffer = malloc(outputBufferLen);

	uint8_t *const iv = outputBuffer;
	uint8_t *const tag = outputBuffer + GCM_IV_LEN;
	uint8_t *ctxt = tag + GCM_TAG_LEN;

	SecRandomCopyBytes(kSecRandomDefault, GCM_IV_LEN, iv);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	assert(1 == EVP_EncryptInit(&ctx, EVP_aes_128_gcm(), key.bytes, iv));

	const uint8_t *ptxt = message.bytes;
	size_t plen = message.length;

	int len;
	while (plen > UINT32_MAX) {
		assert(1 == EVP_EncryptUpdate(&ctx, ctxt, &len, ptxt, UINT32_MAX));
		ctxt += len;
		ptxt += UINT32_MAX;
		plen -= UINT32_MAX;
	}
	if (plen) {
		assert(1 == EVP_EncryptUpdate(&ctx, ctxt, &len, ptxt, (uint32_t)plen));
		ctxt += len;
	}

	assert(1 == EVP_EncryptFinal_ex(&ctx, ctxt, &len));
	ctxt += len;

	assert(1 == EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag));

	EVP_CIPHER_CTX_cleanup(&ctx);

	return [NSData dataWithBytesNoCopy:outputBuffer length:ctxt - outputBuffer];
}

@end
