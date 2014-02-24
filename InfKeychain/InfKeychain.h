//==============================================================================
//
//  InfKeychain.h
//
//  Copyright 2013 InfinitApps LLC. All rights reserved.
//
//------------------------------------------------------------------------------
//
//  Based on STKeychain.h from https://github.com/ldandersen/STUtils
//
//  Created by Buzz Andersen on 3/7/11.
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

#import <Foundation/Foundation.h>

//------------------------------------------------------------------------------

extern NSString* InfKeychainErrorDomain;
enum {
	InfKeychainErrorCodeNilParameter = -2000,
	InfKeychainErrorCodePreviouslyStoredPasswordMissing = -1999
};

//------------------------------------------------------------------------------

@interface InfKeychain : NSObject

+ (NSString*) passwordForUsername: (NSString*) username
					  serviceName: (NSString*) serviceName
							error: (NSError**) error;

+ (BOOL) storeUsername: (NSString*) username
		   andPassword: (NSString*) password
		forServiceName: (NSString*) serviceName
		updateExisting: (BOOL) updateExisting
				 error: (NSError**) error;

+ (BOOL) deleteItemForUsername: (NSString*) username
				   serviceName: (NSString*) serviceName
						 error: (NSError**) error;

@end

//------------------------------------------------------------------------------
