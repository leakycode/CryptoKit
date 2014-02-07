//
// CryptoKit
// Tests/CKSHA.m
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


#import "CKSHA.h"

#import <XCTest/XCTest.h>

@interface CKSHATests : XCTestCase

@end

@implementation CKSHATests

- (void)testSHA1
{
    NSData *data = [@"hello world\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *digest = [[CKSHA1 digest:data] extractData];
    const uint8_t expected[] = {0x22, 0x59, 0x63, 0x63, 0xb3, 0xde, 0x40, 0xb0, 0x6f, 0x98, 0x1f, 0xb8, 0x5d, 0x82, 0x31, 0x2e, 0x8c, 0x0e, 0xd5, 0x11};
    XCTAssert([[NSData dataWithBytes:expected length:sizeof(expected)] isEqualToData:digest]);
}

- (void)testSHA256
{
    NSData *data = [@"hello world\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *digest = [[CKSHA256 digest:data] extractData];
    const uint8_t expected[] = {0xa9, 0x48, 0x90, 0x4f, 0x2f, 0x0f, 0x47, 0x9b, 0x8f, 0x81, 0x97, 0x69, 0x4b, 0x30, 0x18, 0x4b, 0x0d, 0x2e, 0xd1, 0xc1, 0xcd, 0x2a, 0x1e, 0xc0, 0xfb, 0x85, 0xd2, 0x99, 0xa1, 0x92, 0xa4, 0x47};
    XCTAssert([[NSData dataWithBytes:expected length:sizeof(expected)] isEqualToData:digest]);
}

- (void)testSHA384
{
    NSData *data = [@"hello world\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *digest = [[CKSHA384 digest:data] extractData];
    const uint8_t expected[] = {0x6b, 0x3b, 0x69, 0xff, 0x0a, 0x40, 0x4f, 0x28, 0xd7, 0x5e, 0x98, 0xa0, 0x66, 0xd3, 0xfc, 0x64, 0xff, 0xfd, 0x99, 0x40, 0x87, 0x0c, 0xc6, 0x8b, 0xec, 0xe2, 0x85, 0x45, 0xb9, 0xa7, 0x50, 0x86, 0xb3, 0x43, 0xd7, 0xa1, 0x36, 0x68, 0x38, 0x08, 0x3e, 0x4b, 0x8f, 0x3c, 0xa6, 0xfd, 0x3c, 0x80};
    XCTAssert([[NSData dataWithBytes:expected length:sizeof(expected)] isEqualToData:digest]);
}

- (void)testSHA512
{
    NSData *data = [@"hello world\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *digest = [[CKSHA512 digest:data] extractData];
    const uint8_t expected[] = {0xdb, 0x39, 0x74, 0xa9, 0x7f, 0x24, 0x07, 0xb7, 0xca, 0xe1, 0xae, 0x63, 0x7c, 0x00, 0x30, 0x68, 0x7a, 0x11, 0x91, 0x32, 0x74, 0xd5, 0x78, 0x49, 0x25, 0x58, 0xe3, 0x9c, 0x16, 0xc0, 0x17, 0xde, 0x84, 0xea, 0xcd, 0xc8, 0xc6, 0x2f, 0xe3, 0x4e, 0xe4, 0xe1, 0x2b, 0x4b, 0x14, 0x28, 0x81, 0x7f, 0x09, 0xb6, 0xa2, 0x76, 0x0c, 0x3f, 0x8a, 0x66, 0x4c, 0xea, 0xe9, 0x4d, 0x24, 0x34, 0xa5, 0x93};
    XCTAssert([[NSData dataWithBytes:expected length:sizeof(expected)] isEqualToData:digest]);
}

@end
