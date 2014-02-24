//==============================================================================
//
//  InfKeychain.m
//
//  Copyright 2013 InfinitApps LLC. All rights reserved.
//
//------------------------------------------------------------------------------
//
//  Based on InfKeychain.m from https://github.com/ldandersen/STUtils
//
//  Created by Buzz Andersen on 10/20/08.
//  Based partly on code by Jonathan Wight, Jon Crosby, and Mike Malone.
//  Copyright 2011 System of Touch. All rights reserved.
//
//------------------------------------------------------------------------------
//
//  Permission is hereby granted, free of charge, to any person
//  obtaining a copy of this software and associated documentation
//  files (the "Software"), to deal in the Software without
//  restriction, including without limitation the rights to use,
//  copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following
//  conditions:
//
//  The above copyright notice and this permission notice shall be
//  included in all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
//  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//  OTHER DEALINGS IN THE SOFTWARE.
//
//==============================================================================

#import "InfKeychain.h"

#import <Security/Security.h>

#define USE_MAC_KEYCHAIN_API !TARGET_OS_IPHONE || (TARGET_IPHONE_SIMULATOR && __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_3_0)

//------------------------------------------------------------------------------

NSString *InfKeychainErrorDomain = @"InfKeychainErrorDomain";

//==============================================================================

@implementation InfKeychain

//------------------------------------------------------------------------------
#if USE_MAC_KEYCHAIN_API
//------------------------------------------------------------------------------

+ (NSString*) passwordForUsername: (NSString*) username
					  serviceName: (NSString*) serviceName
							error: (NSError**) error
{
	if (!username || !serviceName) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: InfKeychainErrorCodeNilParameter
									 userInfo: nil];
		}
		
		return nil;
	}
	
	NSError* getError = nil;
	SecKeychainItemRef item = [InfKeychain getKeychainItemReferenceForUsername: username
																   serviceName: serviceName
																		 error: &getError];
	
	if (getError || !item) {
		if (error != NULL) {
			*error = getError;
		}
		
		return nil;
	}
	
	// from Advanced Mac OS X Programming, ch. 16
	UInt32 length;
	char* password;
	SecKeychainAttribute attributes[8];
	SecKeychainAttributeList list;
	
	attributes[0].tag = kSecAccountItemAttr;
	attributes[1].tag = kSecDescriptionItemAttr;
	attributes[2].tag = kSecLabelItemAttr;
	attributes[3].tag = kSecModDateItemAttr;
	
	list.count = 4;
	list.attr = attributes;
	
	OSStatus status = SecKeychainItemCopyContent(item, NULL, &list, &length, (void**) &password);
	
	if (status != noErr) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return nil;
	}
	
	NSString* passwordString = nil;
	
	if (password != NULL) {
		char passwordBuffer[1024];
		
		if (length > 1023) {
			length = 1023;
		}
		
		strncpy(passwordBuffer, password, length);
		
		passwordBuffer[length] = '\0';
		passwordString = [NSString stringWithCString: passwordBuffer
											encoding: NSUTF8StringEncoding];
	}
	
	SecKeychainItemFreeContent(&list, password);
	
	CFRelease(item);
	
	return passwordString;
}

//------------------------------------------------------------------------------

+ (BOOL) storeUsername: (NSString*) username
		   andPassword: (NSString*) password
		forServiceName: (NSString*) serviceName
		updateExisting: (BOOL) updateExisting
				 error: (NSError**) error
{
	if (!username || !password || !serviceName) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: InfKeychainErrorCodeNilParameter
									 userInfo: nil];
		}
		
		return NO;
	}
	
	OSStatus status = noErr;
	
	NSError* getError = nil;
	SecKeychainItemRef item = [InfKeychain getKeychainItemReferenceForUsername: username
																   serviceName: serviceName
																		 error: &getError];
	
	if (getError && [getError code] != noErr) {
		if (error != NULL) {
			*error = getError;
		}
		
		return NO;
	}
	
	if (error != NULL) {
		*error = nil;
	}
	
	if (item) {
		status = SecKeychainItemModifyAttributesAndData(item, NULL,
		                                                (UInt32) [password lengthOfBytesUsingEncoding: NSUTF8StringEncoding],
		                                                [password UTF8String]);
		
		CFRelease(item);
	}
	else {
		status = SecKeychainAddGenericPassword(NULL,
											   (UInt32) [serviceName lengthOfBytesUsingEncoding: NSUTF8StringEncoding],
											   [serviceName UTF8String],
											   (UInt32) [username lengthOfBytesUsingEncoding: NSUTF8StringEncoding],
											   [username UTF8String],
											   (UInt32) [password lengthOfBytesUsingEncoding: NSUTF8StringEncoding],
											   [password UTF8String],
											   NULL);
	}
	
	if (status != noErr) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return NO;
	}
	
	return YES;
}

//------------------------------------------------------------------------------

+ (BOOL) deleteItemForUsername: (NSString*) username
				   serviceName: (NSString*) serviceName
						 error: (NSError**) error
{
	if (!username || !serviceName) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: InfKeychainErrorCodeNilParameter
									 userInfo: nil];
		}
		
		return NO;
	}
	
	if (error != NULL) {
		*error = nil;
	}
	
	NSError* getError = nil;
	SecKeychainItemRef item = [InfKeychain getKeychainItemReferenceForUsername: username
																   serviceName: serviceName
																		 error: &getError];
	
	if (getError && [getError code] != noErr) {
		if (error != NULL) {
			*error = getError;
		}
		
		return NO;
	}
	
	OSStatus status;
	
	if (item) {
		status = SecKeychainItemDelete(item);
		
		CFRelease(item);
	}
	
	if (status != noErr) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return NO;
	}
	
	return YES;
}

//------------------------------------------------------------------------------

// NOTE: Item reference passed back by reference must be released!
+ (SecKeychainItemRef) getKeychainItemReferenceForUsername: (NSString*) username
											   serviceName: (NSString*) serviceName
													 error: (NSError**) error
{
	if (!username || !serviceName) {
		*error = [NSError errorWithDomain: InfKeychainErrorDomain
									 code: InfKeychainErrorCodeNilParameter
								 userInfo: nil];
		return nil;
	}
	
	*error = nil;
	
	SecKeychainItemRef item;
	
	OSStatus status = SecKeychainFindGenericPassword(NULL,
	                                                 (UInt32)[serviceName lengthOfBytesUsingEncoding: NSUTF8StringEncoding],
	                                                 [serviceName UTF8String],
	                                                 (UInt32)[username lengthOfBytesUsingEncoding: NSUTF8StringEncoding],
	                                                 [username UTF8String],
	                                                 NULL,
	                                                 NULL,
	                                                 &item);
	
	if (status != noErr) {
		if (status != errSecItemNotFound) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return nil;
	}
	
	return item;
}

//------------------------------------------------------------------------------
#else
//------------------------------------------------------------------------------

+ (NSString*) passwordForUsername: (NSString*) username
					  serviceName: (NSString*) serviceName
							error: (NSError**) error
{
	if (!username || !serviceName) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: InfKeychainErrorCodeNilParameter
									 userInfo: nil];
		}
		
		return nil;
	}
	
	if (error != NULL) {
		*error = nil;
	}
	
	// Set up a query dictionary with the base query attributes: item type (generic), username, and service
	
	NSDictionary* query = @{
		(__bridge id) kSecClass       : (__bridge id) kSecClassGenericPassword,
		(__bridge id) kSecAttrAccount : username,
		(__bridge id) kSecAttrService : serviceName,
	};
	
	// First do a query for attributes, in case we already have a Keychain item with no password data set.
	
	NSMutableDictionary* attributeQuery = [query mutableCopy];
	//	[attributeQuery setObject:(id)kCFBooleanTrue forKey: kSecReturnAttributes];
	attributeQuery[(__bridge id) kSecReturnAttributes] = @YES;
	
	CFTypeRef attributeResult = nil;
	OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) attributeQuery, &attributeResult);
	
	if (status != noErr) {
		// No existing item found--simply return nil for the password
		if (error != NULL && status != errSecItemNotFound) {
			// Only return an error if a real exception happened--not simply for "not found."
			*error = [NSError errorWithDomain: InfKeychainErrorDomain code: status userInfo: nil];
		}
		
		return nil;
	}
	if (attributeResult) {
		CFRelease(attributeResult);
	}
	
	// We have an existing item, now query for the password data associated with it.
	
	NSMutableDictionary* passwordQuery = [query mutableCopy];
//	[passwordQuery setObject: kCFBooleanTrue forKey: kSecReturnData];
	passwordQuery[(__bridge id) kSecReturnData] = @YES;
	
	CFTypeRef passwordResult = NULL;
	status = SecItemCopyMatching((__bridge CFDictionaryRef) passwordQuery, &passwordResult);
	NSData* resultData = (__bridge_transfer NSData*) passwordResult;
	
	if (status != noErr) {
		if (status == errSecItemNotFound) {
			// We found attributes for the item previously, but no password now, so return a special error.
			// Users of this API will probably want to detect this error and prompt the user to
			// re-enter their credentials.  When you attempt to store the re-entered credentials
			// using storeUsername:andPassword:forServiceName:updateExisting:error
			// the old, incorrect entry will be deleted and a new one with a properly encrypted
			// password will be added.
			if (error != NULL) {
				*error = [NSError errorWithDomain: InfKeychainErrorDomain
				                             code: InfKeychainErrorCodePreviouslyStoredPasswordMissing
				                         userInfo: nil];
			}
		}
		else if (error != NULL) {
			// Something else went wrong. Simply return the normal Keychain API error code.
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return nil;
	}
	
	NSString* password = nil;
	
	if (resultData) {
		password = [[NSString alloc] initWithData: resultData
										 encoding: NSUTF8StringEncoding];
	}
	else if (error != NULL) {
		// There is an existing item, but we weren't able to get password data for it for some reason.
		// Set the error so the code above us can prompt the user again.
		*error = [NSError errorWithDomain: InfKeychainErrorDomain
		                             code: InfKeychainErrorCodePreviouslyStoredPasswordMissing
		                         userInfo: nil];
	}
	
	return password;
}

//------------------------------------------------------------------------------

+ (BOOL) storeUsername: (NSString*) username
		   andPassword: (NSString*) password
		forServiceName: (NSString*) serviceName
		updateExisting: (BOOL) updateExisting
				 error: (NSError**) error
{
	if (!username || !password || !serviceName) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: InfKeychainErrorCodeNilParameter
									 userInfo: nil];
		}
		
		return NO;
	}
	
	// See if we already have a password entered for these credentials.
	NSError* getError = nil;
	NSString* existingPassword = [InfKeychain passwordForUsername: username
													  serviceName: serviceName
															error: &getError];
	
	if ([getError code] == InfKeychainErrorCodePreviouslyStoredPasswordMissing) {
		// There is an existing entry without a password properly stored.
		// Delete the existing item before moving on entering a correct one.
		
		getError = nil;
		
		[self deleteItemForUsername: username
						serviceName: serviceName
							  error: &getError];
		
		if ([getError code] != noErr) {
			if (error != NULL) {
				*error = getError;
			}
			
			return NO;
		}
	}
	else if ([getError code] != noErr) {
		if (error != NULL) {
			*error = getError;
		}
		
		return NO;
	}
	
	if (error != NULL) {
		*error = nil;
	}
	
	OSStatus status = noErr;
	
	if (existingPassword) {
		// We have an existing, properly entered item with a password.
		// Update the existing item.
		
		if (![existingPassword isEqualToString: password] && updateExisting) {
			// Only update if we're allowed to update existing.  If not, simply do nothing.
				
			NSDictionary* query = @{
				(__bridge id) kSecClass       : (__bridge id) kSecClassGenericPassword,
				(__bridge id) kSecAttrService : serviceName,
				(__bridge id) kSecAttrLabel   : serviceName,
				(__bridge id) kSecAttrAccount : username,
			};
			
			NSDictionary* newDataDictionary = @{
				(__bridge id) kSecValueData : [password dataUsingEncoding: NSUTF8StringEncoding],
			};
			
			status = SecItemUpdate((__bridge CFDictionaryRef) query,
								   (__bridge CFDictionaryRef) newDataDictionary);
		}
	}
	else {
		// No existing entry (or an existing, improperly entered, and therefore now
		// deleted, entry).  Create a new entry.
		
		NSDictionary* query = @{
			(__bridge id) kSecClass       : (__bridge id) kSecClassGenericPassword,
			(__bridge id) kSecAttrService : serviceName,
			(__bridge id) kSecAttrLabel   : serviceName,
			(__bridge id) kSecAttrAccount : username,
			(__bridge id) kSecValueData   : [password dataUsingEncoding: NSUTF8StringEncoding],
		};
		
		status = SecItemAdd((__bridge CFDictionaryRef) query, NULL);
	}
	
	if (status != noErr) {
		// Something went wrong with adding the new item. Return the Keychain error code.
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return NO;
	}
	
	return YES;
}

//------------------------------------------------------------------------------

+ (BOOL) deleteItemForUsername: (NSString*) username
				   serviceName: (NSString*) serviceName
						 error: (NSError**) error
{
	if (!username || !serviceName) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: InfKeychainErrorCodeNilParameter
									 userInfo: nil];
		}
		
		return NO;
	}
	
	if (error != NULL) {
		*error = nil;
	}
	
	NSDictionary* query = @{
		(__bridge id) kSecClass            : (__bridge id) kSecClassGenericPassword,
		(__bridge id) kSecAttrAccount      : username,
		(__bridge id) kSecAttrService      : serviceName,
		(__bridge id) kSecReturnAttributes : @YES,
	};
	
	OSStatus status = SecItemDelete((__bridge CFDictionaryRef) query);
	
	if (status != noErr) {
		if (error != NULL) {
			*error = [NSError errorWithDomain: InfKeychainErrorDomain
										 code: status userInfo: nil];
		}
		
		return NO;
	}
	
	return YES;
}

//------------------------------------------------------------------------------
#endif
//------------------------------------------------------------------------------

@end

//==============================================================================
