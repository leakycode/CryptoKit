#import "CKSensitiveBuffer.h"

@protocol CKMessageDigest

+ (NSUInteger)digestLength;
+ (CKSensitiveBuffer *)digest:(id<CKData>)message;

@end
