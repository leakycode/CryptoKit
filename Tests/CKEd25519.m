#import <XCTest/XCTest.h>

#import "CKEd25519.h"

@interface CKEd25519Tests : XCTestCase

@end

@implementation CKEd25519Tests

- (void)testLengths
{
	XCTAssert([CKEd25519 privateKeyLength] == 64);
	XCTAssert([CKEd25519 publicKeyLength] == 32);
	XCTAssert([CKEd25519 signatureLength] == 64);
	XCTAssert([CKEd25519 sharedSecretLength] == 32);
}

- (void)testKeyGeneration
{
	CKSensitiveBuffer *key = [CKEd25519 randomPrivateKey];
	XCTAssert(key.length == [CKEd25519 privateKeyLength]);

	NSData *publicKey = [CKEd25519 publicKeyForPrivateKey:key];
	XCTAssert(publicKey.length == [CKEd25519 publicKeyLength]);
	CKSensitiveBuffer *key2 = [CKEd25519 randomPrivateKey];

	XCTAssertNotNil(key2);
	XCTAssert(key2.length == [CKEd25519 privateKeyLength]);
	XCTAssertFalse([[key extractData] isEqualToData:[key2 extractData]]);
}

- (void)testSigning
{
	CKSensitiveBuffer *key = [CKEd25519 randomPrivateKey];
	NSData *data = [@"Thanks, DJB for the awesome public domain implementation of ed25519!" dataUsingEncoding:NSUTF8StringEncoding];
	NSData *signature = [CKEd25519 sign:data withPrivateKey:key];
	NSData *pubKey = [CKEd25519 publicKeyForPrivateKey:key];
	XCTAssertTrue([CKEd25519 verifySignature:signature ofMessage:data byPublicKey:pubKey]);

	NSMutableData *corruptData = [data mutableCopy];
	uint8_t* bytes = corruptData.mutableBytes;
	bytes[10] = 'C';
	
	signature = [CKEd25519 sign:corruptData withPrivateKey:key];
	XCTAssertFalse([CKEd25519 verifySignature:signature ofMessage:data byPublicKey:pubKey]);
}

- (void)testKeyExchange
{
	CKSensitiveBuffer *k1 = [CKEd25519 randomPrivateKey];
	CKSensitiveBuffer *k2 = [CKEd25519 randomPrivateKey];
	XCTAssert(memcmp(k1.bytes, k2.bytes, [CKEd25519 privateKeyLength]));
	
	CKSensitiveBuffer *sec1 = [CKEd25519 sharedSecretWithPrivateKey:k1 andPublicKey:[CKEd25519 publicKeyForPrivateKey:k2]];
	XCTAssert(sec1.length == [CKEd25519 sharedSecretLength]);
	CKSensitiveBuffer *sec2 = [CKEd25519 sharedSecretWithPrivateKey:k2 andPublicKey:[CKEd25519 publicKeyForPrivateKey:k1]];
	XCTAssert(sec2.length == [CKEd25519 sharedSecretLength]);
	
	XCTAssertFalse(memcmp(sec1.bytes, sec2.bytes, [sec1 length]));
	
	CKSensitiveBuffer *k3 = [CKEd25519 randomPrivateKey];
	CKSensitiveBuffer *sec3 = [CKEd25519 sharedSecretWithPrivateKey:k1 andPublicKey:[CKEd25519 publicKeyForPrivateKey:k3]];
	XCTAssert(sec3.length == [CKEd25519 sharedSecretLength]);
	XCTAssert(memcmp(sec1.bytes, sec3.bytes, [sec1 length]));
}

@end
