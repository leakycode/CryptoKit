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
