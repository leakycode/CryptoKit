#import <Foundation/Foundation.h>

@protocol CKData

- (const uint8_t *)bytes;
- (NSUInteger)length;

@end

@interface NSData (CKDataAdditions) <CKData>

@end