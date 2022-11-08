#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "SecAccessControlPriv.h"
#import "SecItemPriv.h"
#import "SecKeyPriv.h"
#import "SecKeyPriv2.h"
#import "SecCertificatePriv.h"
#import "SecIdentityPriv.h"
#import "substrate.h"
#import <dlfcn.h>

// SecAccessControl
SecAccessControlRef (*orig_SecAccessControlCreate)(CFAllocatorRef allocator, CFErrorRef *error);
SecAccessControlRef my_SecAccessControlCreate(CFAllocatorRef allocator, CFErrorRef *error)
{
    NSLog(@"SecAccessControlCreate was called.");
    SecAccessControlRef r = orig_SecAccessControlCreate(allocator, error);
    NSLog(@"SecAccessControlRef: %@",r);
    return r;
}


SecAccessControlRef (*orig_SecAccessControlCreateWithFlags)(CFAllocatorRef __nullable allocator, CFTypeRef protection, SecAccessControlCreateFlags flags, CFErrorRef *error)
SecAccessControlRef my_SecAccessControlCreateWithFlags(CFAllocatorRef __nullable allocator, CFTypeRef protection, SecAccessControlCreateFlags flags, CFErrorRef *error)
{
    NSLog(@"SecAccessControlCreateWithFlags was called.");
    SecAccessControlRef r = orig_SecAccessControlCreateWithFlags(allocator, protection, flags, error);
    NSLog(@"SecAccessControlRef: %@\nprotection: %@\nflags: %@",r,protection,flags);
    return r;
}


bool (*orig_SecAccessControlSetProtection)(SecAccessControlRef access_control, CFTypeRef protection, CFErrorRef *error);
bool my_SecAccessControlSetProtection(SecAccessControlRef access_control, CFTypeRef protection, CFErrorRef *error)
{
    NSLog(@"SecAccessControlSetProtection was called.")
    bool r = orig_SecAccessControlSetProtection(access_control, protection, error);
    NSLog(@"SetProtection: %d\nAccess Control: %@\nprotection: %@",r,access_control,protection);
    return r;
}


//SecCertificate
OSStatus (*orig_SecCertificateCopyCommonName)(SecCertificateRef certificate, CFStringRef * __nonnull CF_RETURNS_RETAINED commonName);
OSStatus my_SecCertificateCopyCommonName(SecCertificateRef certificate, CFStringRef * __nonnull CF_RETURNS_RETAINED commonName)
{
    NSLog(@"SecCertificateCopyCommonName was called.");
    OSStatus r = orig_SecCertificateCopyCommonName(certificate,commonName);
    return r;
}

CFDataRef (*orig_SecCertificateCopyData)(SecCertificateRef certificate)
CFDataRef my_SecCertificateCopyData(SecCertificateRef certificate)
{
    NSLog(@"SecCertificateCopyData was called.");
    CFDataRef r = orig+SecCertificateCopyData(certificate);
    return r;
}

//SecCertificateCopyExtensionValue

SecKeyRef (*orig_SecCertificateCopyKey)(SecCertificateRef certificate);
SecKeyRef my_SecCertificateCopyKey(SecCertificateRef certificate)
{
    NSLog(@"SecCertificateCopyKey was called.");
    SecKeyRef r = orig_SecCertificateCopyKey(certificate);
    return r;
}

CFArrayRef (*orig_SecCertificateCopyProperties)(SecCertificateRef certificate);
CFArrayRef my_SecCertificateCopyProperties(SecCertificateRef certificate)
{
    NSLog(@"SecCertificateCopyProperties was called.");
    CFArrayRef r = orig_SecCertificateCopyProperties(certificate);
    return r;
}

OSStatus (*orig_SecCertificateCreateFromData)(const CSSM_DATA *data, CSSM_CERT_TYPE type, CSSM_CERT_ENCODING encoding, SecCertificateRef * __nonnull certificate);
OSStatus my_SecCertificateCreateFromData(const CSSM_DATA *data, CSSM_CERT_TYPE type, CSSM_CERT_ENCODING encoding, SecCertificateRef * __nonnull certificate)
{
    NSLog(@"SecCertificateCreateFromData was called.");
    OSStatus r = orig_SecCertificateCreateFromData(data, type, encoding, certificate);
    return r;
}

bool (*orig_SecCertificateIsValid)(SecCertificateRef certificate, CFAbsoluteTime verifyTime);
bool my_SecCertificateIsValid(SecCertificateRef certificate, CFAbsoluteTime verifyTime)
{
    NSLog(@"SecCertificateIsValid was called");
    bool r = orig_SecCertificateIsValid(certificate, verifyTime);
    return YES;
}

CFDataRef (*orig_SecGenerateCertificateRequestWithParameters)(SecRDN _Nonnull * _Nonnull subject, CFDictionaryRef _Nullable parameters, SecKeyRef _Nullable publicKey, SecKeyRef privateKey);
CFDataRef my_SecGenerateCertificateRequestWithParameters(SecRDN _Nonnull * _Nonnull subject, CFDictionaryRef _Nullable parameters, SecKeyRef _Nullable publicKey, SecKeyRef privateKey)
{
    NSLog(@"SecGenerateCertificateRequestWithParameters");
    CFDataRef = orig_SecGenerateCertificateRequestWithParameters(subject, parameters, publicKey, privateKey);
    NSLog(@"Certificate Request: %@\nsubject: %@\nparameters: %@\npublicKey: %p\nprivateKey: %p",r,subject,parameters,publicKey,privateKey);
    return r;
}


//SecIdentity

OSStatus (*orig_SecIdentityCopyCertificate)(SecIdentityRef identityRef, SecCertificateRef * __nonnull certificateRef);
OSStatus my_SecIdentityCopyCertificate(SecIdentityRef identityRef, SecCertificateRef * __nonnull certificateRef)
{
    NSLog(@"SecIdentityCopyCertificate was called.");
    OSStatus r = orig_SecIdentityCopyCertificate(identityRef, certificateRef);
    return r;
}

OSStatus (*orig_SecIdentityCopyPrivateKey)(SecIdentityRef identityRef, SecKeyRef * __nonnull privateKeyRef);
OSStatus my_SecIdentityCopyPrivateKey(SecIdentityRef identityRef, SecKeyRef * __nonnull privateKeyRef)
{
    NSLog(@"SecIdentityCopyPrivateKey was called.");
    OSStatus r = orig_SecIdentityCopyPrivateKey(identityRef, privateKeyRef);
    return r;
}

SecIdentityRef (*orig_SecIdentityCreate)(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);
SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey)
{
    NSLog(@"SecIdentityRef was called.");
    SecIdentityRef r = orig_SecIdentityCreate(allocator, certificate, privateKey);
    return r;
}

//SecKey

CFDictionaryRef (*orig_SecKeyCopyAttributes)(SecKeyRef key);
CFDictionaryRef my_SecKeyCopyAttributes(SecKeyRef key)
{
    NSLog(@"SecKeyCopyAttributes was called.");
    CFDictionaryRef r = orig_SecKeyCopyAttributes(key);
    NSLog(@"SecKeyCopyAttributes: %@\nfrom key: %p",r,key);
    return r;
}

CFDataRef (*orig_SecKeyCopyExternalRepresentation)(SecKeyRef key, CFErrorRef* error);
CFDataRef my_SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef* error)
{
    NSLog(@"SecKeyCopyExternalRepresentation was called.");
    CFDataRef r = orig_SecKeyCopyExternalRepresentation(key, error);
    return r;
}

SecKeyRef _Nullable (*orig_SecKeyCopyPublicKey)(SecKeyRef key);
SecKeyRef _Nullable my_SecKeyCopyPublicKey(SecKeyRef key)
{
    NSLog(@"SecKeyCopyPublicKey was called.");
    SecKeyRef r = orig_SecKeyCopyPublicKey(key);
    return r;
}

SecKeyRef (*orig_SecKeyCopySystemKey)(SecKeySystemKeyType keyType, CFErrorRef* error);
SecKeyRef my_SecKeyCopySystemKey(SecKeySystemKeyType keyType, CFErrorRef* error)
{
    NSLog(@"SecKeyCopySystemKey was called.");
    SecKeyRef r = orig_SecKeyCopySystemKey(keyType, error);
    NSLog(@"SecKeyCopySystemKey: %p\nwithType: %d",r,keyType);
    return r;
}

CFDataRef (*orig_SecKeyCreateAttestation)(SecKeyRef key, SecKeyRef keyToAttest, CFErrorRef* error);
CFDataRef my_SecKeyCreateAttestation(SecKeyRef key, SecKeyRef keyToAttest, CFErrorRef* error)
{
    NSLog(@"SecKeyCreateAttestation was called.");
    CFDataRef r = orig_SecKeyCreateAttestation(key,keyToAttest, error);
    NSLog(@"SecKeyCreateAttestation: %@",r);
    return r;
}

SecKeyRef (*orig_SecKeyCreateRSAPublicKey_ios)(CFAllocatorRef allocator, const uint8_t *keyData, CFIndex keyDataLength, SecKeyEncoding encoding);
SecKeyRef my_SecKeyCreateRSAPublicKey_ios(CFAllocatorRef allocator, const uint8_t *keyData, CFIndex keyDataLength, SecKeyEncoding encoding)
{
    NSLog(@"SecKeyCreateRSAPublicKey_ios");
    SecKeyRef r = orig_SecKeyCreateRSAPublicKey_ios(allocator, keyData, keyDataLength, encoding);
    return r;
}

SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef attributes, CFErrorRef* error);
SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef attributes CFErrorRef* error)
{
    NSLog(@"SecKeyCreateRandomKey was called.");
    SecKeyRef r = orig_SecKeyCreateRandomKey(attributes, error);
    NSLog(@"SecKeyCreateRandomKey: %p\nattributes:\n%@",r,attributes);
  //  CFDictionaryRef attr = SecKeyCopyAttributes(r);
  //  NSLog(@"SecKeyRef attributes: %@",attr);
    return r;
}

CFDataRef _Nullable (*orig_SecKeyCreateSignature)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error);
CFDataRef _Nullable my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error)
{
    NSLog(@"SecKeyCreateSignature was called.");
    CFDataRef r = orig_SecKeyCreateSignature(key,algorithm,dataToSign, error);
    return r;
}


SecKeyRef (*orig_SecKeyCreateWithData)(CFDataRef keyData, CFDictionaryRef attributes, CFErrorRef* error);
SecKeyRef my_SecKeyCreateWithData(CFDataRef keyData, CFDictionaryRef attributes, CFErrorRef* error)
{
    NSLog(@"SecKeyCreateWithData Called.");
    SecKeyRef r = orig_SecKeyCreateWithData(keyData, attributes, error);
    NSLog(@"SecKeyCreateWithData: %p\nData: %@\nattributes: %@",r,keyData,attributes);
    return r;
}

/*
size_t (*orig_SecKeyGetBlockSize)(SecKeyRef key);
size_t my_SecKeyGetBlockSize(SecKeyRef key)
{
    NSLog(@"SecKeyGetBlockSize was called");
    size_t r = orig_SecKeyGetBlockSize(key);
    return r;z
}

OSStatus (*orig_SecKeyRawSign)(
                       SecKeyRef           key,
                       SecPadding          padding,
                       const uint8_t       *dataToSign,
                       size_t              dataToSignLen,
                       uint8_t             *sig,
                       size_t              *sigLen);

OSStatus my_SecKeyRawSign(
                       SecKeyRef           key,
                       SecPadding          padding,
                       const uint8_t       *dataToSign,
                       size_t              dataToSignLen,
                       uint8_t             *sig,
                       size_t              *sigLen)
{
    NSLog(@"SecKeyRawSign was called.");
    OSStatus r = orig_SecKeyRawSign(key, padding, dataToSign, dataToSignLen, sig, sigLen);
    return r;
}

OSStatus (*orig_SecKeyRawVerify)(
                         SecKeyRef           key,
                         SecPadding          padding,
                         const uint8_t       *signedData,
                         size_t              signedDataLen,
                         const uint8_t       *sig,
                         size_t              sigLen);
OSStatus my_SecKeyRawVerify(
                         SecKeyRef           key,
                         SecPadding          padding,
                         const uint8_t       *signedData,
                         size_t              signedDataLen,
                         const uint8_t       *sig,
                         size_t              sigLen)
{
    NSLog(@"SecKeyRawVerify was called.");
    OSStatus r = orig_SecKeyRawVerify(key, padding, signedData, signedDataLen, sig, sigLen);
    return r;                    
}
*/
Boolean (*orig_SecKeySetParameter)(SecKeyRef key, CFStringRef name, CFPropertyListRef value, CFErrorRef *error);
Boolean my_SecKeySetParameter(SecKeyRef key, CFStringRef name, CFPropertyListRef value, CFErrorRef *error)
{
    NSLog(@"SecKeySetParameter was called.");
    Boolean r = orig_SecKeySetParameter(key, name, value, error);
    return r;
}

/*

//SecPolicy

SecPolicyCreateFactoryDeviceCertificate

SecPolicyCreateiPhoneActivation

SecPolicyCreateiPhoneDeviceCertificate

//SecTrust

SecTrustCopyFailureDescription

SecTrustCopyPublicKey

SecTrustCreateWithCertificates

SecTrustEvaluate

SecTrustSetAnchorCertificates

//SecItem

SecItemAdd

SecItemCopyMatching

SecItemDelete
*/

%ctor {
    MSHookFunction(SecAccessControlCreate, my_SecAccessControlCreate, &orig_SecAccessControlCreate);
    MSHookFunction(SecAccessControlCreateFlags, my_SecAccessControlCreateWithFlags, &orig_SecAccessControlCreateWithFlags);
    MSHookFunction(SecAccessControlSetProtection, my_SecAccessControlSetProtection, &orig_SecAccessControlSetProtection);
    MSHookFunction(SecCertificateCopyCommonName, my_SecCertificateCopyCommonName, &orig_SecCertificateCopyCommonName);
    MSHookFunction(SecCertificateCopyData, my_SecCertificateCopyData, &orig_SecCertificateCopyData);
    MSHookFunction(SecCertificateCopyKey, my_SecCertificateCopyKey, &orig_SecCertificateCopyKey);
    MSHookFunction(SecCertificateCopyProperties, my_SecCertificateCopyProperties, &orig_SecCertificateCopyProperties);
    MSHookFunction(SecCertificateCreateFromData, my_SecCertificateCreateFromData &orig_SecCertificateCreateFromData);
    MSHookFunction(SecCertificateIsValid, my_SecCertificateIsValid, &orig_SecCertificateIsValid);
    MSHookFunction(SecGenerateCertificateRequestWithParameters, my_SecGenerateCertificateRequestWithParameters, &orig_SecGenerateCertificateRequestWithParameters);
    MSHookFunction(SecKeyCopyAttributes, my_SecKeyCopyAttributes &orig_SecKeyCopyAttributes);
    MSHookFunction(SecKeyCopyExternalRepresentation, my_SecKeyCopyExternalRepresentation, &orig_SecKeyCopyExternalRepresentation);
    MSHookFunction(SecKeyCopyPublicKey, my_SecKeyCopyPublicKey, &orig_SecKeyCopyPublicKey);
    MSHookFunction(SecKeyCopySystemKey, my_SecKeyCopySystemKey &orig_SecKeyCopySystemKey);
    MSHookFunction(SecKeyCreateAttestation, my_SecKeyCreateAttestation, &orig_SecKeyCreateAttestation);
    MSHookFunction(SecKeyCreateRandomKey, my_SecKeyCreateRandomKey, &orig_SecKeyCreateRandomKey);
    MSHookFunction(SecKeyCreateRSAPublicKey_ios, my_SecKeyCreateRSAPublicKey_ios, &orig_SecKeyCreateRSAPublicKey_ios);
    MSHookFunction(SecKeyCreateSignature, my_SecKeyCreateSignature, &orig_SecKeyCreateSignature);
    MSHookFunction(SecKeyCreateWithData, my_SecKeyCreateWithData, &orig_SecKeyCreateWithData);
    MSHoookFunction(SecKeySetParameter, my_SecKeySetParameter, &orig_SecKeySetParameter);

}
