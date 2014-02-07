//
// CryptoKit
// CKSHA.m
// 
// Copyright (c) 2014 Mehrdad Afshari
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//


#import "CKSHA.h"

#import <CommonCrypto/CommonDigest.h>

@implementation CKSHA1

+ (NSUInteger)digestLength
{
	return CC_SHA1_DIGEST_LENGTH;
}

+ (CKSensitiveBuffer *)digest:(id<CKData>)message;
{
	uint8_t *hash = malloc(CC_SHA1_DIGEST_LENGTH);
	CC_SHA1_CTX ctx;
	CC_SHA1_Init(&ctx);
	CC_SHA1_Update(&ctx, [message bytes], (CC_LONG)[message length]);
	CC_SHA1_Final(hash, &ctx);
	return [CKSensitiveBuffer bufferWithBytes:hash length:CC_SHA1_DIGEST_LENGTH];
}

@end

@implementation CKSHA256

+ (NSUInteger)digestLength
{
	return CC_SHA256_DIGEST_LENGTH;
}

+ (CKSensitiveBuffer *)digest:(id<CKData>)message;
{
	uint8_t *hash = malloc(CC_SHA256_DIGEST_LENGTH);
	CC_SHA256_CTX ctx;
	CC_SHA256_Init(&ctx);
	CC_SHA256_Update(&ctx, [message bytes], (CC_LONG)[message length]);
	CC_SHA256_Final(hash, &ctx);
	return [CKSensitiveBuffer bufferWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
}

@end

@implementation CKSHA384

+ (NSUInteger)digestLength
{
	return CC_SHA384_DIGEST_LENGTH;
}

+ (CKSensitiveBuffer *)digest:(id<CKData>)message;
{
	uint8_t *hash = malloc(CC_SHA384_DIGEST_LENGTH);
	CC_SHA512_CTX ctx;
	CC_SHA384_Init(&ctx);
	CC_SHA384_Update(&ctx, [message bytes], (CC_LONG)[message length]);
	CC_SHA384_Final(hash, &ctx);
	return [CKSensitiveBuffer bufferWithBytes:hash length:CC_SHA384_DIGEST_LENGTH];
}

@end

@implementation CKSHA512

+ (NSUInteger)digestLength
{
	return CC_SHA512_DIGEST_LENGTH;
}

+ (CKSensitiveBuffer *)digest:(id<CKData>)message;
{
	uint8_t *hash = malloc(CC_SHA512_DIGEST_LENGTH);
	CC_SHA512_CTX ctx;
	CC_SHA512_Init(&ctx);
	CC_SHA512_Update(&ctx, [message bytes], (CC_LONG)[message length]);
    CC_SHA512_Final(hash, &ctx);
	return [CKSensitiveBuffer bufferWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
}

@end
