#import "CKKeyExchange.h"
#import "CKDigitalSignature.h"

@interface CKEd25519 : NSObject <CKDigitalSignature, CKKeyExchange>

@end
