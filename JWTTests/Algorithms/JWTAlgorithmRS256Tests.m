//
//  JWTAlgorithmRS256Tests.m
//  JWT
//
//  Created by Marcelo Schroeder on 11/03/2016.
//  Copyright © 2016 Karma. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "JWT.h"
#import "MF_Base64Additions.h"

@interface JWTAlgorithmRS256Tests : XCTestCase

@property(nonatomic) NSString *validTokenToDecode;
@property(nonatomic) NSString *invalidTokenToDecode;
@property(nonatomic) NSString *validPublicKeyCertificateString;
@property(nonatomic) NSString *invalidPublicKeyCertificateString;
@property(nonatomic) NSData *privateKeyCertificateData;
@property(nonatomic) NSString *algorithmName;
@property(nonatomic) NSDictionary *headerAndPayloadDictionary;
@end

@implementation JWTAlgorithmRS256Tests

- (void)testEncodeCertificateDataWithValidPrivateKeyCertificatePassphrase {
    NSString *token = [JWTBuilder encodePayload:self.headerAndPayloadDictionary].secretData(self.privateKeyCertificateData).privateKeyCertificatePassphrase(@"password").algorithmName(self.algorithmName).encode;
    [self assertToken:token];
}

- (void)testEncodeCertificateDataWithInvalidPrivateKeyCertificatePassphrase {
    NSString *token = [JWTBuilder encodePayload:self.headerAndPayloadDictionary].secretData(self.privateKeyCertificateData).privateKeyCertificatePassphrase(@"incorrect password").algorithmName(self.algorithmName).encode;
    XCTAssertNil(token);
}

- (void)testEncodeCertificateStringWithValidPrivateKeyCertificatePassphrase {
    NSString *certificateString = [self.privateKeyCertificateData base64UrlEncodedString];
    NSString *token = [JWTBuilder encodePayload:self.headerAndPayloadDictionary].secret(certificateString).privateKeyCertificatePassphrase(@"password").algorithmName(self.algorithmName).encode;
    [self assertToken:token];
}

- (void)testEncodeCertificateStringWithInvalidPrivateKeyCertificatePassphrase {
    NSString *certificateString = [self.privateKeyCertificateData base64UrlEncodedString];
    NSString *token = [JWTBuilder encodePayload:self.headerAndPayloadDictionary].secret(certificateString).privateKeyCertificatePassphrase(@"incorrect password").algorithmName(self.algorithmName).encode;
    XCTAssertNil(token);
}

- (void)testThatDecodeCertificateStringSucceedsWithValidSignatureAndValidPublicKey {
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.validTokenToDecode].secret(self.validPublicKeyCertificateString).algorithmName(self.algorithmName).decode;
    [self assertDecodedDictionary:decodedDictionary];
}

- (void)testThatDecodeCertificateStringFailsWithInValidSignatureAndValidPublicKey {
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.invalidTokenToDecode].secret(self.validPublicKeyCertificateString).algorithmName(self.algorithmName).decode;
    XCTAssertNil(decodedDictionary);
}

- (void)testThatDecodeCertificateStringFailsWithValidSignatureAndInvalidPublicKey {
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.validTokenToDecode].secret(self.invalidPublicKeyCertificateString).algorithmName(self.algorithmName).decode;
    XCTAssertNil(decodedDictionary);
}

- (void)testThatDecodeCertificateDataSucceedsWithValidSignatureAndValidPublicKey {
    NSData *certificateData = [NSData dataWithBase64UrlEncodedString:self.validPublicKeyCertificateString];
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.validTokenToDecode].secretData(certificateData).algorithmName(self.algorithmName).decode;
    [self assertDecodedDictionary:decodedDictionary];
}

- (void)testThatDecodeCertificateDataFailsWithInValidSignatureAndValidPublicKey {
    NSData *certificateData = [NSData dataWithBase64UrlEncodedString:self.validPublicKeyCertificateString];
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.invalidTokenToDecode].secretData(certificateData).algorithmName(self.algorithmName).decode;
    XCTAssertNil(decodedDictionary);
}

- (void)testThatDecodeCertificateDataFailsWithValidSignatureAndInvalidPublicKey {
    NSData *certificateData = [NSData dataWithBase64UrlEncodedString:self.invalidPublicKeyCertificateString];
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.validTokenToDecode].secretData(certificateData).algorithmName(self.algorithmName).decode;
    XCTAssertNil(decodedDictionary);
}

#pragma mark - Overrides

- (void)setUp {
    [super setUp];
    self.validTokenToDecode     = @"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.plYqcrAN-UceGdRPYVacV1DT_EinFNdPHDRzyDwWBCI23XkyDSH9Z4h3KppLV66iq5zIwVYNOJel6ND_1QSG0TbsnRHjb3B1N3vdwRa_VEC23c2mgsL3FntpR_StfeBeikfb5ftVhi-EhtIrbccniOcjiPstGNuGYtNl2uG6pS1rQCPthAPRDmNfQvtg6aMJNufo-n6pUsWpaKqSU5Tau8HuPPQwqsYwqKzOymYMr3B_fT5rO2OzxBLn7xin3uPs-x-741QEo3PSstdCdpLlNAlZIxvUBnn8ow8Ln1L_soM84VqEieNzdWD-bbWrlJYEa5LvRTEMcLBPFx3IutQlkAUW4Dg0Ws02K_87VRtb40kqNKzakvIT3ZLsfcNS4OFGzkjBSfUkMndMhTQEs3UH8vY8uAqToDB6Y5DaPIm3KqaEPoZds_FB6e5h4eIr5lm7pJGvXxiqalh--Yoz-R71aqpSUnACAFsUN4MnjAtIqWakjUSNJPNEWuevRLjmWjSp_pk99RhMXImC7GHkHhe9b9uwM6j1Xzxi0TwCEpqOSj9WMHWMbzPdT3Xrk82aBKIg1qXNhLyDcEpsTpvbKPsVZXnu4fheNWXtBWTGFPrQATljrt-6z_D6gIU-5EWu1E8X7X7c_Gb4NGOBRgMfuYFKBtkfs3zceGLuM0qA6ubz4OA";
    self.invalidTokenToDecode   = @"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6InlvdSJ9.plYqcrAN-UceGdRPYVacV1DT_EinFNdPHDRzyDwWBCI23XkyDSH9Z4h3KppLV66iq5zIwVYNOJel6ND_1QSG0TbsnRHjb3B1N3vdwRa_VEC23c2mgsL3FntpR_StfeBeikfb5ftVhi-EhtIrbccniOcjiPstGNuGYtNl2uG6pS1rQCPthAPRDmNfQvtg6aMJNufo-n6pUsWpaKqSU5Tau8HuPPQwqsYwqKzOymYMr3B_fT5rO2OzxBLn7xin3uPs-x-741QEo3PSstdCdpLlNAlZIxvUBnn8ow8Ln1L_soM84VqEieNzdWD-bbWrlJYEa5LvRTEMcLBPFx3IutQlkAUW4Dg0Ws02K_87VRtb40kqNKzakvIT3ZLsfcNS4OFGzkjBSfUkMndMhTQEs3UH8vY8uAqToDB6Y5DaPIm3KqaEPoZds_FB6e5h4eIr5lm7pJGvXxiqalh--Yoz-R71aqpSUnACAFsUN4MnjAtIqWakjUSNJPNEWuevRLjmWjSp_pk99RhMXImC7GHkHhe9b9uwM6j1Xzxi0TwCEpqOSj9WMHWMbzPdT3Xrk82aBKIg1qXNhLyDcEpsTpvbKPsVZXnu4fheNWXtBWTGFPrQATljrt-6z_D6gIU-5EWu1E8X7X7c_Gb4NGOBRgMfuYFKBtkfs3zceGLuM0qA6ubz4OA";

    // From "Test certificate and public key 1.pem"
    self.validPublicKeyCertificateString    = @"MIIFtTCCA52gAwIBAgIJALqHwUIiDq3qMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTYwNjE0MDcxMTQ2WhcNMTcwNjE0MDcxMTQ2WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtTyxkXvnonyUHfejLuSUCcsq5cAWv+bPcF37C1sqJep061XzmQTZXMtMh9tiZsVZF0mZoDtWiBoVGLWfJNiDHCik0zjsLIcyngqAziDYEByuWSWjg4RnxodcVgHN6g17Aqw6hqTVGQL4OQKIulA2+M+ZojdfmiYAPSA+gbMVaxDLDYCFk+2ZpXS66jmT/ngPz7u/yCeoMzlMPc2Axm1yhOOOgYmxssDfCO1Ups+KYR3bBo8V2f6HKkHf8y+GEZf5bEDNBOR8tOnW2l74zon4s4wxp4WjzQljEyn8ofkQc3n0qocJl05JsDet12eokMgY7NnCWv9r8HkzsfYXQnp5RPZR9exP9XC0CBmvDu1/XYkOpYskcKcNLUDpGvzCENXRk+5uvBbN0evU1oukxN+3YjBLeirByqNeI1cNv8tKAO6sADT2Y3rtpLSRPlNHNQPpzevD4QV8xJz4PWWT56k4me3+cTN4aY/cjbCKZFWhBdCNg81rUv7PVALvPhLJXKu9oH4usKvCiaGsuO5YhaTEJmZhonsrud5Jd8env/0FgyRjhZ1xqNidK9IOeJ9lnfs7o5Cthrq6GkBekhxac/4XuUxX66lEfw08PP/TXI3LXnOD83GHr6bD/AH+nA2WrDmtHMt8K/mpYvYofZu1BL3TVREVHLmTl7kf0iEL6Mq8LmsCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUCXH4lMVsxA2Q31voX598WP3hKccwdQYDVR0jBG4wbIAUCXH4lMVsxA2Q31voX598WP3hKcehSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQC6h8FCIg6t6jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4ICAQCkCmMDNNemrcMZXgBxno1Dnw+6317+nlzScPkW7GBG7RN6IteHffXPdManqC5UqnCC8UAWPW7105d+4DYKBEImsN/2ab30k78bXEyAKrIfm/nKVZ792RD9/vW7HdOjEr+ugglxwqDSMqxW3N/DCLWEc8m6Z5dzpLAp11nr+fDUUYGtxjWeepFTwYP7y1ldsLAcRH9wheVOWrirIbIeTNcDHM1pnbIt57ehurjl71XtqbVxrcSxC/RdHG0MNGyeelbXALeHdazw6YRqcmoGojkctEUCOYXQU8+YjwhHtMIpR4tVkWvHeNrZCtG7eJ7agTtPgIHvBS19UMh3EYjbwQzRI6ByB5zMDLlxXgKNmHPhH4wkW1uIG4xOmlFRdFVSvbGt3N79Y46MeuR8N+BbOCGibPeHeH2dtVyNkgyZt5YFsaCkQUZs3ZIkyuaOJMntT6xaw0rw+gKZSsowGin7B5E14NByb0KO6HIYyBo15tD1u60mh3ieEOexKwA8F6rU6bjUcpOHHKTjil6S2PnvhLsNBr2XDViM1qZLJCoYGCQE/liJsODrHDyJEZFWZop237cAnJR+cTFRMURCjOQWxLq6qLgSKVlK1a/2BVwfAhBLh5K6VNsFnweTNavCIwPDzwBdP9fxr957wDAdKaJp77pfEtC3pupUDA4bvooy0l/q9w==";

    // From "Test certificate and public key 2.pem"
    self.invalidPublicKeyCertificateString  = @"MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBMMR8wHQYDVQQDDBZEaWdpdGFsIFNpZ25pbmcgVGVzdCAyMQswCQYDVQQGEwJBVTEcMBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTAeFw0xNjAzMTIwMDUzMDJaFw0xNzAzMTIwMDUzMDJaMEwxHzAdBgNVBAMMFkRpZ2l0YWwgU2lnbmluZyBUZXN0IDIxCzAJBgNVBAYTAkFVMRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQ57lsgAE5eWahnJ4e9InudO6rtJ12qE/qaeBrU8qcmJ0ku78Ih2gnShRtdmJGaDgGH1hM6J+ucQvl87foNqJPeAN+s5GeiGw4yoaHTnibJ9/v8rzz+PzMwXn6EGykaL6eDAIIOKNcMXvjWZEXtwr/roOFbaEIe6JeqNeSb2mXS+1XI5NGCL4jp8y0WmNCp/0LUMGQyj2ilmIgaV74cB2xdxPozZZJnWDASkgbGzi4ijZCpOP/yksEvJ7JSNBmmAQoFNslMymOO3XYJs3yvR9thwRl/uHbY4gHRPGHramCdJ6s+Lw+gzCjslB87HsIy4pp6PeDiOe/tyc79LWcsLbQIDAQABo0QwQjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwQwGAYDVR0RBBEwD4ENdGVzdEB0ZXN0LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAmlDHOKSdE8sRbUHNWZtyghm7FUBcrEEB/mM/dtRbq7aUFEPtHpXdKGf/fC0TZxdLoKfIFvgEuPlvzwgFhHTW3qzY4dES0n2krALVkfT0IR72vR98AGEE2gchSqGtwr1KkvYE8A4IwU+mlrDzVZoE0OjRg73Klpaxc77ln34CB+yAIlL1uunIZj+zmCuhsK4i6QAjzJ1PaNXo5P9F4zfJDW4B0ej6/2V9nxBvWW8hdba/eVbDltkvw0dZZay6YgBmVz9mXbAGZ6pk2XOjTlS3XLFgLUVe8WTXbktQw0cCcf3xfn6HB/Y+5l/0srZ3i5Su5qtdDDbZ3epBjB3K5kiP8g==";

    self.algorithmName = @"RS256";
    self.headerAndPayloadDictionary = @{
            @"header" : @{
                    @"alg" : @"RS256",
                    @"typ" : @"JWT",
            },
            @"payload" : @{
                    @"hello" : @"world",
            }
    };
    NSString *p12FilePath = [[NSBundle bundleForClass:[JWTAlgorithmRS256Tests class]] pathForResource:@"Test certificate and private key 1"
                                                                                               ofType:@"p12"];
    self.privateKeyCertificateData = [NSData dataWithContentsOfFile:p12FilePath];
}

#pragma mark - Private

- (void)assertDecodedDictionary:(NSDictionary *)decodedDictionary {
    XCTAssertNotNil(decodedDictionary);
    XCTAssertEqualObjects(decodedDictionary, self.headerAndPayloadDictionary);
}

- (void)assertToken:(NSString *)token {
    XCTAssertNotNil(token);
    NSDictionary *decodedDictionary = [JWTBuilder decodeMessage:self.validTokenToDecode].secret(self.validPublicKeyCertificateString).algorithmName(self.algorithmName).decode;
    [self assertDecodedDictionary:decodedDictionary];
    NSLog(@"token = %@", token);
}

@end
