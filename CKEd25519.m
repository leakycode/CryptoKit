//
// CryptoKit
//
// The MIT License (MIT)
//
// Copyright (c) 2014 Mehrdad Afshari
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//


#import "CKEd25519.h"

#import "ed25519/ed25519.h"
#import <Security/SecRandom.h>

#define ED25519_PRIVATE_KEY_LEN 64
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_SIGNATURE_LEN 64
#define ED25519_SHARED_SECRET_LEN 32

@implementation CKEd25519

+ (NSUInteger)privateKeyLength
{
	return ED25519_PRIVATE_KEY_LEN;
}

+ (NSUInteger)publicKeyLength
{
	return ED25519_PUBLIC_KEY_LEN;
}

+ (NSUInteger)signatureLength
{
	return ED25519_SIGNATURE_LEN;
}

+ (NSUInteger)sharedSecretLength
{
	return ED25519_SHARED_SECRET_LEN;
}

+ (CKSensitiveBuffer *)randomPrivateKey
{
	uint8_t seed[64];
	SecRandomCopyBytes(kSecRandomDefault, sizeof(seed), seed);
	uint8_t *privateKey = malloc(ED25519_PRIVATE_KEY_LEN);
	ed25519_create_privatekey(privateKey, seed);
	memset_s(seed, sizeof(seed), 64, sizeof(seed));
	return [CKSensitiveBuffer bufferWithBytes:privateKey length:ED25519_PRIVATE_KEY_LEN];
}

+ (NSData *)publicKeyForPrivateKey:(id<CKData>)privateKey
{
	uint8_t *publicKey = malloc(ED25519_PUBLIC_KEY_LEN);
	ed25519_derive_publickey(publicKey, privateKey.bytes);
	return [NSData dataWithBytesNoCopy:publicKey length:ED25519_PUBLIC_KEY_LEN];
}

+ (NSData *)sign:(id<CKData>)message withPrivateKey:(id<CKData>)privateKey
{
	return [self sign:message withPrivateKey:privateKey andPublicKey:[self publicKeyForPrivateKey:privateKey]];
}

+ (NSData *)sign:(id<CKData>)message withPrivateKey:(id<CKData>)privateKey andPublicKey:(id<CKData>)publicKey
{
	uint8_t *signature = malloc(ED25519_SIGNATURE_LEN);
	ed25519_sign(signature, message.bytes, message.length, publicKey.bytes, privateKey.bytes);
	return [NSData dataWithBytesNoCopy:signature length:ED25519_SIGNATURE_LEN];
}

+ (BOOL)verifySignature:(id<CKData>)signature ofMessage:(id<CKData>)message byPublicKey:(id<CKData>)publicKey
{
	return ed25519_verify(signature.bytes, message.bytes, message.length, publicKey.bytes);
}

+ (CKSensitiveBuffer *)sharedSecretWithPrivateKey:(id<CKData>)privateKey andPublicKey:(id<CKData>)publicKey
{
	uint8_t *sharedSecret = malloc(ED25519_SHARED_SECRET_LEN);
	ed25519_key_exchange(sharedSecret, publicKey.bytes, privateKey.bytes);
	return [CKSensitiveBuffer bufferWithBytes:sharedSecret length:ED25519_SHARED_SECRET_LEN];
}

@end
