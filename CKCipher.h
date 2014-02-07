#import "CKSensitiveBuffer.h"

@protocol CKCipher

+ (NSUInteger)keyLength;

+ (CKSensitiveBuffer *)decrypt:(id<CKData>)message key:(id<CKData>)key;
+ (NSData *)encrypt:(id<CKData>)message key:(id<CKData>)key;

@end
