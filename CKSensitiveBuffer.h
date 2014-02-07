#import "CKData.h"

@interface CKSensitiveBuffer : NSObject <CKData>

+ (CKSensitiveBuffer *)randomBufferOfLength:(NSUInteger)length;
+ (CKSensitiveBuffer *)bufferWithBytes:(uint8_t *)bytes length:(NSUInteger)length;
- (CKSensitiveBuffer *)initWithBytes:(uint8_t *)bytes length:(NSUInteger)length;
- (const uint8_t *)bytes NS_RETURNS_INNER_POINTER;
- (NSUInteger)length;
- (void)discard;
- (NSMutableData *)extractMutableData;
- (NSData *)extractData;

@end
