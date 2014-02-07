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
