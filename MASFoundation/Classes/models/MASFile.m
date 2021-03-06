//
//  MASFile.m
//  MASFoundation
//
//  Copyright (c) 2016 CA, Inc.
//
//  This software may be modified and distributed under the terms
//  of the MIT license. See the LICENSE file for details.
//

#import "MASFile.h"

#import "MASIFileManager.h"
#import "MASFileService.h"


@interface MASFile ()

- (id)init NS_UNAVAILABLE;

@end


@implementation MASFile


# pragma mark - Creating a new file

+ (MASFile *)fileWithName:(NSString *)name contents:(NSData *)contents
{
    return [[MASFileService sharedService] fileWithName:name contents:contents];
}


- (id)init
{
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:@"init is not a valid initializer, please use a factory method"
                                 userInfo:nil];
    return nil;
}


- (NSString *)debugDescription
{
    return [NSString stringWithFormat:@"(%@) file name: %@\n\n        content data length: %ld\n        path: %@",
        [self class], [self name], (unsigned long)[self contents].length, [self filePath]];
}


# pragma mark - Finding a file

+ (MASFile *)findFileWithName:(NSString *)name;
{
    return [[MASFileService sharedService] findFileWithName:name];
}


+ (MASFile *)findFileWithName:(NSString *)name password:(NSString *)password
{
    return [[MASFileService sharedService] findFileWithName:name password:password];
}


# pragma mark - Secure Storage

- (BOOL)saveWithPassword:(NSString *)password
{
    // Overwritten
    
    return NO;
}


+ (NSString *)storeTemporaryItem:(NSData *)data
{
    NSString *randomName = [NSString randomStringWithLength:20];
    
    //
    // Generate the full file path in the Temporary Directory
    //
    NSString *filePath = [MASIFileManager pathForTemporaryDirectoryWithPath:randomName];
        
    [MASIFileManager writeFileAtPath:filePath content:data];
    
    //DLog(@"called and returned file path: %@", filePath);
    
    return filePath;
}


+ (BOOL)removeItemAtFilePath:(NSString *)filePath
{
    return [MASIFileManager removeItemAtPath:filePath];
}

@end
