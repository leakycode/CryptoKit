#import "CKSensitiveBuffer.h"

@protocol CKDigitalSignature

+ (NSUInteger)privateKeyLength;
+ (NSUInteger)publicKeyLength;
+ (NSUInteger)signatureLength;

+ (CKSensitiveBuffer *)randomPrivateKey;
+ (NSData *)publicKeyForPrivateKey:(id<CKData>)privateKey;
+ (NSData *)sign:(id<CKData>)message withPrivateKey:(id<CKData>)privateKey;
+ (NSData *)sign:(id<CKData>)message withPrivateKey:(id<CKData>)privateKey andPublicKey:(id<CKData>)publicKey;
+ (BOOL)verifySignature:(id<CKData>)signature ofMessage:(id<CKData>)message byPublicKey:(id<CKData>)publicKey;

@end
