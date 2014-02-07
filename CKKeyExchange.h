#import "CKSensitiveBuffer.h"

@protocol CKKeyExchange

+ (NSUInteger)privateKeyLength;
+ (NSUInteger)publicKeyLength;
+ (NSUInteger)sharedSecretLength;

+ (CKSensitiveBuffer *)randomPrivateKey;
+ (NSData *)publicKeyForPrivateKey:(id<CKData>)privateKey;
+ (CKSensitiveBuffer *)sharedSecretWithPrivateKey:(id<CKData>)privateKey andPublicKey:(id<CKData>)publicKey;

@end
