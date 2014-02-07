#import "CKSensitiveBuffer.h"

#import <Security/SecRandom.h>

@implementation CKSensitiveBuffer {
	uint8_t *_bytes;
	NSUInteger _length;
}

- (CKSensitiveBuffer *)initWithBytes:(uint8_t *)bytes length:(NSUInteger)length
{
	if (self = [super init]) {
		_bytes = bytes;
		_length = length;
	}
	return self;
}

- (const uint8_t *)bytes NS_RETURNS_INNER_POINTER
{
	return _bytes;
}

- (NSUInteger)length
{
	return _length;
}

- (void)discard
{
	if (_bytes) {
		memset_s(_bytes, _length, 0, _length);
		free(_bytes);
		_bytes = nil;
		_length = 0;
	}
}

- (NSMutableData *)extractMutableData
{
	NSMutableData *data = [[NSMutableData alloc] initWithBytesNoCopy:_bytes length:_length];
	_bytes = nil;
	_length = 0;
	return data;
}

- (NSData *)extractData
{
	NSData *data = [NSData dataWithBytesNoCopy:_bytes length:_length];
	_bytes = nil;
	_length = 0;
	return data;
}

- (void)dealloc
{
	[self discard];
}

+ (CKSensitiveBuffer *)bufferWithBytes:(uint8_t *)bytes length:(NSUInteger)length
{
	return [[CKSensitiveBuffer alloc] initWithBytes:bytes length:length];
}

+ (CKSensitiveBuffer *)randomBufferOfLength:(NSUInteger)length
{
	uint8_t *buffer = malloc(length);
	SecRandomCopyBytes(kSecRandomDefault, length, buffer);
	return [self bufferWithBytes:buffer length:length];
}

@end
