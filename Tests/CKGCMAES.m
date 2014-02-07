//
// CryptoKit
// Tests/CKGCMAES.m
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


#import <XCTest/XCTest.h>

#import "CKGCMAES.h"

@interface CKGCMAESTests : XCTestCase

@end

@implementation CKGCMAESTests

- (void)testEncryption
{
	CKSensitiveBuffer *key = [CKSensitiveBuffer randomBufferOfLength:[CKGCMAES keyLength]];
	NSData *expected = [@"Thanks Rijndael! Trying out GCM authentication too!" dataUsingEncoding:NSUTF8StringEncoding];
	NSData *encrypted = [CKGCMAES encrypt:expected key:key];
	XCTAssert(encrypted.length);
	NSData *actual = [[CKGCMAES decrypt:encrypted key:key] extractData];
	XCTAssert([expected isEqualToData:actual]);
	
	NSMutableData *corruptData = [encrypted mutableCopy];
	((uint8_t*)corruptData.mutableBytes)[42] = 42;
	XCTAssertNil([CKGCMAES decrypt:corruptData key:key]);
}

@end
