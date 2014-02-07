//
// CryptoKit
// CKSensitiveBuffer.m
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
		[self disown];
	}
}

- (NSString *)extractUTF8String
{
	NSString *str = [[NSString alloc] initWithBytesNoCopy:_bytes length:_length encoding:NSUTF8StringEncoding freeWhenDone:YES];
	[self disown];
	return str;
}

- (NSMutableData *)extractMutableData
{
	NSMutableData *data = [[NSMutableData alloc] initWithBytesNoCopy:_bytes length:_length];
	[self disown];
	return data;
}

- (NSData *)extractData
{
	NSData *data = [NSData dataWithBytesNoCopy:_bytes length:_length];
	[self disown];
	return data;
}

- (void)disown
{
	_bytes = nil;
	_length = 0;
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
