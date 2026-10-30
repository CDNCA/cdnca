//go:build darwin && cgo

package dnsproviderlive

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static OSStatus cdnca_keychain_copy(
    const UInt8 *service, CFIndex service_len,
    const UInt8 *account, CFIndex account_len,
    UInt8 **output, CFIndex *output_len) {
	CFStringRef service_ref = CFStringCreateWithBytes(
		kCFAllocatorDefault, service, service_len, kCFStringEncodingUTF8, false);
	CFStringRef account_ref = CFStringCreateWithBytes(
		kCFAllocatorDefault, account, account_len, kCFStringEncodingUTF8, false);
	if (service_ref == NULL || account_ref == NULL) {
		if (service_ref != NULL) CFRelease(service_ref);
		if (account_ref != NULL) CFRelease(account_ref);
		return errSecParam;
	}
	const void *keys[] = {
		kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit
	};
	const void *values[] = {
		kSecClassGenericPassword, service_ref, account_ref, kCFBooleanTrue, kSecMatchLimitOne
	};
	CFDictionaryRef query = CFDictionaryCreate(
		kCFAllocatorDefault, keys, values, 5,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(service_ref);
	CFRelease(account_ref);
	if (query == NULL) return errSecAllocate;
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) return status;
	if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
		if (result != NULL) CFRelease(result);
		return errSecDecode;
	}
	CFDataRef data = (CFDataRef)result;
	CFIndex length = CFDataGetLength(data);
	if (length <= 0 || length > 65535) {
		CFRelease(result);
		return errSecDecode;
	}
	UInt8 *copy = malloc((size_t)length);
	if (copy == NULL) {
		CFRelease(result);
		return errSecAllocate;
	}
	memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
	CFRelease(result);
	*output = copy;
	*output_len = length;
	return errSecSuccess;
}

static void cdnca_zero_free(UInt8 *value, CFIndex length) {
	if (value == NULL) return;
	volatile UInt8 *cursor = value;
	for (CFIndex index = 0; index < length; index++) cursor[index] = 0;
	free(value);
}
*/
import "C"

import "unsafe"

func ReadKeychain(service, account string) ([]byte, error) {
	if !validAlias(service) || !validAlias(account) {
		return nil, ErrCredentialUnavailable
	}
	serviceBytes := []byte(service)
	accountBytes := []byte(account)
	defer zero(serviceBytes)
	defer zero(accountBytes)
	var output *C.UInt8
	var outputLength C.CFIndex
	status := C.cdnca_keychain_copy(
		(*C.UInt8)(unsafe.Pointer(&serviceBytes[0])), C.CFIndex(len(serviceBytes)),
		(*C.UInt8)(unsafe.Pointer(&accountBytes[0])), C.CFIndex(len(accountBytes)),
		&output, &outputLength,
	)
	if status != C.errSecSuccess || output == nil || outputLength <= 0 {
		return nil, ErrCredentialUnavailable
	}
	defer C.cdnca_zero_free(output, outputLength)
	if outputLength > C.CFIndex(^uint(0)>>1) {
		return nil, ErrCredentialUnavailable
	}
	return C.GoBytes(unsafe.Pointer(output), C.int(outputLength)), nil
}
