//
// MASFoundationService.m
//  MASFoundation
//
//  Copyright (c) 2016 CA, Inc.
//
//  This software may be modified and distributed under the terms
//  of the MIT license. See the LICENSE file for details.
//

#import "MASNetworkingService.h"

#import "MASConstantsPrivate.h"
#import "MASConfigurationService.h"

#import "MASAccessService.h"
#import "MASDeleteURLRequest.h"
#import "MASGetURLRequest.h"
#import "MASPatchURLRequest.h"
#import "MASPostURLRequest.h"
#import "MASPutURLRequest.h"
#import "MASHTTPSessionManager.h"
#import "MASLocationService.h"
#import "MASModelService.h"
#import "MASINetworking.h"
#import "MASINetworkActivityLogger.h"


# pragma mark - Configuration Constants

//
// Defaults
//
static NSString *const kMASDefaultConfigurationFilename = @"msso_config";
static NSString *const kMASDefaultConfigurationFilenameExtension = @"json";
static NSString *const kMASDefaultNewline = @"\n";
static NSString *const kMASDefaultEmptySpace = @" ";


//
// Network Configuration Keys
//
static NSString *const kMASOAuthConfigurationKey = @"oauth"; // value is Dictionary

# pragma mark - Network Monitoring Constants

NSString *const MASGatewayMonitoringStatusUnknownValue = @"Unknown";
NSString *const MASGatewayMonitoringStatusNotReachableValue = @"Not Reachable";
NSString *const MASGatewayMonitoringStatusReachableViaWWANValue = @"Reachable Via WWAN";
NSString *const MASGatewayMonitoringStatusReachableViaWiFiValue = @"Reachable Via WiFi";



@interface MASNetworkingService ()

# pragma mark - Properties

@property (nonatomic, strong, readonly) MASIHTTPSessionManager *manager;

@end


@implementation MASNetworkingService

static MASGatewayMonitorStatusBlock _gatewayStatusMonitor_;


# pragma mark - Properties

+ (void)setGatewayMonitor:(MASGatewayMonitorStatusBlock)monitor
{
    _gatewayStatusMonitor_ = monitor;
}


#ifdef DEBUG

+ (void)setGatewayNetworkActivityLogging:(BOOL)enabled
{
    //
    // If network activity logging is enabled start it
    //
    if(enabled)
    {
        //
        // Begin logging
        //
        [[MASINetworkActivityLogger sharedLogger] startLogging];
        [[MASINetworkActivityLogger sharedLogger] setLevel:MASILoggerLevelDebug];
    }
    
    //
    // Stop network activity logging
    //
    else
    {
        [[MASINetworkActivityLogger sharedLogger] stopLogging];
    }
}

#endif


# pragma mark - Shared Service

+ (instancetype)sharedService
{
    static id sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^
                  {
                      sharedInstance = [[MASNetworkingService alloc] initProtected];
                  });
    
    return sharedInstance;
}


# pragma mark - Lifecycle

+ (NSString *)serviceUUID
{
    return MASNetworkServiceUUID;
}


- (void)serviceDidLoad
{
    
    [super serviceDidLoad];
}


- (void)serviceWillStart
{
    //
    // establish URLSession with configuration's host name and start networking monitoring
    //
    [self establishURLSession];
    
    [super serviceWillStart];
}


- (void)serviceWillStop
{
    //
    // Cleanup the internal manager and shared instance
    //
    [self.manager.operationQueue cancelAllOperations];
    [self.manager.reachabilityManager stopMonitoring];
    [self.manager.reachabilityManager setReachabilityStatusChangeBlock:nil];
    _manager = nil;
    
    [super serviceWillStop];
}


- (void)serviceDidReset
{
    //
    //
    // Cleanup the internal manager and shared instance
    //
    [self.manager.operationQueue cancelAllOperations];
    [self.manager.reachabilityManager stopMonitoring];
    [self.manager.reachabilityManager setReachabilityStatusChangeBlock:nil];
    _manager = nil;
    
    //
    // Reset the value
    //
    _monitoringStatus = MASGatewayMonitoringStatusUnknown;
    
    [super serviceDidReset];
}


# pragma mark - Public

- (void)establishURLSession
{
    
    //
    // Cleanup the internal manager and shared instance
    //
    [self.manager.operationQueue cancelAllOperations];
    [self.manager.reachabilityManager stopMonitoring];
    [self.manager.reachabilityManager setReachabilityStatusChangeBlock:nil];
    _manager = nil;
    
    //
    // Retrieve the configuration
    //
    MASConfiguration *configuration = [MASConfiguration currentConfiguration];
    
    //
    //  Setup the security policy
    //
    //  Certificate Pinning Mode
    //
    
    MASISSLPinningMode pinningMode = MASISSLPinningModeCertificate;
    
    if (configuration.enabledTrustedPublicPKI)
    {
        pinningMode = MASISSLPinningModeNone;
    }
    else if (configuration.enabledPublicKeyPinning) {
        
        pinningMode = MASISSLPinningModePublicKey;
    }
    
    MASISecurityPolicy *policy = [MASISecurityPolicy policyWithPinningMode:pinningMode];
    
    [policy setAllowInvalidCertificates:(pinningMode == MASISSLPinningModeNone ? NO : YES)];
    [policy setValidatesDomainName:NO];
    [policy setValidatesCertificateChain:NO];
    [policy setPinnedCertificates:configuration.gatewayCertificatesAsDERData];
    
    //
    // Create the network manager
    //
    _manager = [[MASHTTPSessionManager alloc] initWithBaseURL:configuration.gatewayUrl];
    _manager.securityPolicy = policy;
    
    //
    // Reachability
    //
    [_manager.reachabilityManager setReachabilityStatusChangeBlock:^(MASINetworkReachabilityStatus status){
        //
        // Set the new value, this should be a direct mapping of MASI and MAS types
        //
        _monitoringStatus = (long)status;
        
        //
        // Make sure it is on the main thread
        //
        dispatch_async(dispatch_get_main_queue(), ^
                       {
                           //
                           // Notify the block, if any
                           //
                           if(_gatewayStatusMonitor_) _gatewayStatusMonitor_((long)status);
                       });
    }];
    
    //
    // Begin monitoring
    //
    [_manager.reachabilityManager startMonitoring];
}


- (NSString *)debugDescription
{
    return [NSString stringWithFormat:@"%@\n\n    base url: %@\n    monitoring status: %@",
            [super debugDescription], _manager.baseURL, [self networkStatusAsString]];
}


# pragma mark - Private

- (MASSessionDataTaskCompletionBlock)sessionDataTaskCompletionBlockWithEndPoint:(NSString *)endPoint
                                                                     parameters:(NSDictionary *)originalParameterInfo
                                                                        headers:(NSDictionary *)originalHeaderInfo
                                                                     httpMethod:(NSString *)httpMethod
                                                                    requestType:(MASRequestResponseType)requestType
                                                                   responseType:(MASRequestResponseType)responseType
                                                                completionBlock:(MASResponseInfoErrorBlock)completion
{
    
    __block MASRequestResponseType blockResponseType = responseType;
    
    MASSessionDataTaskCompletionBlock taskCompletionBlock = ^(NSURLResponse * _Nonnull response, id  _Nonnull responseObject, NSError * _Nonnull error){
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        
        MASIHTTPResponseSerializer *responseSerializer = [MASURLRequest responseSerializerForType:blockResponseType];
        [responseSerializer validateResponse:httpResponse data:responseObject error:&error];
        
        //
        // Response header info
        //
        NSDictionary *headerInfo = [httpResponse allHeaderFields];
        
        //
        //  If the error exists from the server, inject http status code in error userInfo
        //
        if (error)
        {
            //  Mutable copy of userInfo
            NSMutableDictionary *errorUserInfo = [error.userInfo mutableCopy];
            
            //  Add status code
            [errorUserInfo setObject:[NSNumber numberWithInteger:httpResponse.statusCode] forKey:MASErrorStatusCodeRequestResponseKey];
            
            //  Create new error
            NSError *newError = [[NSError alloc] initWithDomain:error.domain code:error.code userInfo:errorUserInfo];
            error = newError;
        }

        __block NSMutableDictionary *responseInfo = [NSMutableDictionary new];
        
        if (headerInfo)
        {
            [responseInfo setObject:headerInfo forKey:MASResponseInfoHeaderInfoKey];
        }
        
        //
        // Response body info
        //
        if (responseObject)
        {
            [responseInfo setObject:responseObject forKey:MASResponseInfoBodyInfoKey];
        }
        
        NSString *magErrorCode = nil;
        
        //
        // Check if MAG error code exists
        //
        if ([[headerInfo allKeys] containsObject:MASHeaderErrorKey])
        {
            magErrorCode = [NSString stringWithFormat:@"%@", [headerInfo objectForKey:MASHeaderErrorKey]];
        }
        
        //
        // If MAG error code exists, and it ends with 990, it means that the token is invalid.
        // Then, try re-validate user's session and retry the request.
        //
        if (magErrorCode && [magErrorCode hasSuffix:@"990"])
        {
            
            //
            // Remove access_token from keychain
            //
            [[MASAccessService sharedService] setAccessValueString:nil withAccessValueType:MASAccessValueTypeAccessToken];
            [[MASAccessService sharedService] setAccessValueNumber:nil withAccessValueType:MASAccessValueTypeExpiresIn];
            [[MASAccessService sharedService].currentAccessObj refresh];
            
            //
            // Validate user's session
            //
            [[MASModelService sharedService] validateCurrentUserSession:^(BOOL completed, NSError *error) {
                
                //
                // If it fails to re-validate session, notify user
                //
                if (!completed || error)
                {
                    if(completion) completion(responseInfo, error);
                }
                else {
                    
                    NSMutableDictionary *newHeader = [originalHeaderInfo mutableCopy];
                    
                    //
                    // Retry request
                    //
                    if ([httpMethod isEqualToString:@"DELETE"])
                    {
                        [self deleteFrom:endPoint withParameters:originalParameterInfo andHeaders:newHeader requestType:requestType responseType:responseType completion:completion];
                    }
                    else if ([httpMethod isEqualToString:@"GET"]) {
                        [self getFrom:endPoint withParameters:originalParameterInfo andHeaders:newHeader requestType:requestType responseType:responseType completion:completion];
                    }
                    else if ([httpMethod isEqualToString:@"PATCH"]) {
                        [self patchTo:endPoint withParameters:originalParameterInfo andHeaders:newHeader requestType:requestType responseType:responseType completion:completion];
                    }
                    else if ([httpMethod isEqualToString:@"POST"]) {
                        [self postTo:endPoint withParameters:originalParameterInfo andHeaders:newHeader requestType:requestType responseType:responseType completion:completion];
                    }
                    else if ([httpMethod isEqualToString:@"PUT"]) {
                        [self putTo:endPoint withParameters:originalParameterInfo andHeaders:newHeader requestType:requestType responseType:responseType completion:completion];
                    }
                    
                    return;
                }
            }];
        }
        else {
            //
            // If the server complains that client_secret or client_id is invalid, we have to clear the client_id and client_secret
            //
            if (magErrorCode && [magErrorCode hasSuffix:@"201"]) {
                
                [[MASAccessService sharedService] setAccessValueString:nil withAccessValueType:MASAccessValueTypeClientId];
                [[MASAccessService sharedService] setAccessValueString:nil withAccessValueType:MASAccessValueTypeClientSecret];
                [[MASAccessService sharedService] setAccessValueString:nil withAccessValueType:MASAccessValueTypeClientExpiration];
            }
            
            if (completion)
            {
                
                //
                // notify
                //
                if (error)
                {
                    //
                    // if error occured
                    //
                    completion(responseInfo, error);
                }
                else {
                    
                    completion(responseInfo, nil);
                }
            }
        }
    };
    
    return taskCompletionBlock;
}

# pragma mark - Network Monitoring

- (BOOL)networkIsReachable
{
    return (self.monitoringStatus != MASGatewayMonitoringStatusNotReachable ||
            self.monitoringStatus != MASGatewayMonitoringStatusUnknown);
}


- (NSString *)networkStatusAsString
{
    //
    // Detect status and respond appropriately
    //
    switch(self.monitoringStatus)
    {
            //
            // Not Reachable
            //
        case MASGatewayMonitoringStatusNotReachable:
        {
            return MASGatewayMonitoringStatusNotReachableValue;
        }
            
            //
            // Reachable Via WWAN
            //
        case MASGatewayMonitoringStatusReachableViaWWAN:
        {
            return MASGatewayMonitoringStatusReachableViaWWANValue;
        }
            
            //
            // Reachable Via WiFi
            //
        case MASGatewayMonitoringStatusReachableViaWiFi:
        {
            return MASGatewayMonitoringStatusReachableViaWiFiValue;
        }
            
            //
            // Default
            //
        default:
        {
            return MASGatewayMonitoringStatusUnknownValue;
        }
    }
}


# pragma mark - HTTP Requests

- (void)deleteFrom:(NSString *)endPoint
    withParameters:(NSDictionary *)parameterInfo
        andHeaders:(NSDictionary *)headerInfo
        completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Default types
    //
    [self deleteFrom:endPoint
      withParameters:parameterInfo
          andHeaders:headerInfo
         requestType:MASRequestResponseTypeJson
        responseType:MASRequestResponseTypeJson
          completion:completion];
}


- (void)deleteFrom:(NSString *)endPoint
    withParameters:(NSDictionary *)parameterInfo
        andHeaders:(NSDictionary *)headerInfo
       requestType:(MASRequestResponseType)requestType
      responseType:(MASRequestResponseType)responseType
        completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Just passthrough
    //
    [self httpDeleteFrom:endPoint
          withParameters:parameterInfo
              andHeaders:headerInfo
             requestType:requestType
            responseType:responseType
              completion:completion];
}


- (void)httpDeleteFrom:(NSString *)endPoint
        withParameters:(NSDictionary *)parameterInfo
            andHeaders:(NSDictionary *)headerInfo
           requestType:(MASRequestResponseType)requestType
          responseType:(MASRequestResponseType)responseType
            completion:(MASResponseInfoErrorBlock)completion
{
    //DLog(@"called");
    
    //
    //  endPoint cannot be nil
    //
    if (!endPoint)
    {
        //
        // Notify
        //
        if(completion) completion(nil, [NSError errorInvalidEndpoint]);
        
        return;
    }
    
    //
    // Determine if we need to add the geo-location header value
    //
    MASConfiguration *configuration = [MASConfiguration currentConfiguration];
    if(configuration.locationIsRequired)
    {
        //
        // Location required but the location services are not currently authorized for use
        //
        if(![MASLocationService isLocationMonitoringAuthorized])
        {
            //
            // Notify
            //
            if(completion) completion(nil, [NSError errorGeolocationServicesAreUnauthorized]);
            
            return;
        }
        
        //
        // Request the one time, currently available location before proceeding
        //
        [[MASLocationService sharedService] startSingleLocationUpdate:^(CLLocation *location, MASLocationMonitoringAccuracy accuracy, MASLocationMonitoringStatus status)
         {
             //
             // If an invalid geolocation result is detected
             //
             if((status != MASLocationMonitoringStatusSuccess && status != MASLocationMonitoringStatusTimedOut) ||
                !location)
             {
                 //
                 // Notify
                 //
                 if(completion) completion(nil, [NSError errorGeolocationIsInvalid]);
                 
                 return;
             }
             
             //
             // Update the header
             //
             NSMutableDictionary *mutableHeaderInfo = [headerInfo mutableCopy];
             mutableHeaderInfo[MASGeoLocationRequestResponseKey] = [location locationAsGeoCoordinates];
             
             //
             // create request
             //
             MASDeleteURLRequest *request = [MASDeleteURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:mutableHeaderInfo requestType:requestType responseType:responseType];
             
             //
             // create dataTask
             //
             NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                          completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                                  parameters:parameterInfo
                                                                                                                     headers:headerInfo
                                                                                                                  httpMethod:request.HTTPMethod
                                                                                                                 requestType:requestType
                                                                                                                responseType:responseType
                                                                                                             completionBlock:completion]];
             
             //
             // resume dataTask
             //
             [dataTask resume];
         }];
        
        return;
    }
    
    //
    // create request
    //
    MASDeleteURLRequest *request = [MASDeleteURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:headerInfo requestType:requestType responseType:responseType];
    
    //
    // create dataTask
    //
    NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                 completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                         parameters:parameterInfo
                                                                                                            headers:headerInfo
                                                                                                         httpMethod:request.HTTPMethod
                                                                                                        requestType:requestType
                                                                                                       responseType:responseType
                                                                                                    completionBlock:completion]];
    //
    // resume dataTask
    //
    [dataTask resume];
}


- (void)getFrom:(NSString *)endPoint
 withParameters:(NSDictionary *)parameterInfo
     andHeaders:(NSDictionary *)headerInfo
     completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Default types
    //
    [self getFrom:endPoint
   withParameters:parameterInfo
       andHeaders:headerInfo
      requestType:MASRequestResponseTypeJson
     responseType:MASRequestResponseTypeJson
       completion:completion];
}


- (void)getFrom:(NSString *)endPoint
 withParameters:(NSDictionary *)parameterInfo
     andHeaders:(NSDictionary *)headerInfo
    requestType:(MASRequestResponseType)requestType
   responseType:(MASRequestResponseType)responseType
     completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Just passthrough
    //
    [self httpGetFrom:endPoint
       withParameters:parameterInfo
           andHeaders:headerInfo
          requestType:requestType
         responseType:responseType
           completion:completion];
}


- (void)httpGetFrom:(NSString *)endPoint
     withParameters:(NSDictionary *)parameterInfo
         andHeaders:(NSDictionary *)headerInfo
        requestType:(MASRequestResponseType)requestType
       responseType:(MASRequestResponseType)responseType
         completion:(MASResponseInfoErrorBlock)completion
{
    //DLog(@"called");
    
    //
    //  endPoint cannot be nil
    //
    if (!endPoint)
    {
        //
        // Notify
        //
        if(completion) completion(nil, [NSError errorInvalidEndpoint]);
        
        return;
    }
    
    //
    // Determine if we need to add the geo-location header value
    //
    MASConfiguration *configuration = [MASConfiguration currentConfiguration];
    if(configuration.locationIsRequired)
    {
        //
        // Location required but the location services are not currently authorized for use
        //
        if(![MASLocationService isLocationMonitoringAuthorized])
        {
            //
            // Notify
            //
            if(completion) completion(nil, [NSError errorGeolocationServicesAreUnauthorized]);
            
            return;
        }
        
        //
        // Request the one time, currently available location before proceeding
        //
        [[MASLocationService sharedService] startSingleLocationUpdate:^(CLLocation *location, MASLocationMonitoringAccuracy accuracy, MASLocationMonitoringStatus status)
         {
             //
             // If an invalid geolocation result is detected
             //
             if((status != MASLocationMonitoringStatusSuccess && status != MASLocationMonitoringStatusTimedOut) ||
                !location)
             {
                 //
                 // Notify
                 //
                 if(completion) completion(nil, [NSError errorGeolocationIsInvalid]);
                 
                 return;
             }
             
             //
             // Update the header
             //
             NSMutableDictionary *mutableHeaderInfo = [headerInfo mutableCopy];
             mutableHeaderInfo[MASGeoLocationRequestResponseKey] = [location locationAsGeoCoordinates];
             
             //
             // create request
             //
             MASGetURLRequest *request = [MASGetURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:mutableHeaderInfo requestType:requestType responseType:responseType];
             
             //
             // create dataTask
             //
             NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                          completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                                  parameters:parameterInfo
                                                                                                                     headers:headerInfo
                                                                                                                  httpMethod:request.HTTPMethod
                                                                                                                 requestType:requestType
                                                                                                                responseType:responseType
                                                                                                             completionBlock:completion]];
             
             //
             // resume dataTask
             //
             [dataTask resume];
         }];
        
        return;
    }
    
    //
    // Else just create the request
    //
    MASGetURLRequest *request = [MASGetURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:headerInfo requestType:requestType responseType:responseType];
    
    //
    // create dataTask
    //
    NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                 completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                         parameters:parameterInfo
                                                                                                            headers:headerInfo
                                                                                                         httpMethod:request.HTTPMethod
                                                                                                        requestType:requestType
                                                                                                       responseType:responseType
                                                                                                    completionBlock:completion]];
    
    //
    // resume dataTask
    //
    [dataTask resume];
}


- (void)patchTo:(NSString *)endPoint
 withParameters:(NSDictionary *)parameterInfo
     andHeaders:(NSDictionary *)headerInfo
     completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Default types
    //
    [self patchTo:endPoint
   withParameters:parameterInfo
       andHeaders:headerInfo
      requestType:MASRequestResponseTypeJson
     responseType:MASRequestResponseTypeJson
       completion:completion];
}


- (void)patchTo:(NSString *)endPoint
 withParameters:(NSDictionary *)parameterInfo
     andHeaders:(NSDictionary *)headerInfo
    requestType:(MASRequestResponseType)requestType
   responseType:(MASRequestResponseType)responseType
     completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Just passthrough
    //
    [self httpPatchTo:endPoint
       withParameters:parameterInfo
           andHeaders:headerInfo
          requestType:requestType
         responseType:responseType
           completion:completion];
}


- (void)httpPatchTo:(NSString *)endPoint
     withParameters:(NSDictionary *)parameterInfo
         andHeaders:(NSDictionary *)headerInfo
        requestType:(MASRequestResponseType)requestType
       responseType:(MASRequestResponseType)responseType
         completion:(MASResponseInfoErrorBlock)completion
{
    //
    //  endPoint cannot be nil
    //
    if (!endPoint)
    {
        //
        // Notify
        //
        if(completion) completion(nil, [NSError errorInvalidEndpoint]);
        
        return;
    }
    
    //
    // Determine if we need to add the geo-location header value
    //
    MASConfiguration *configuration = [MASConfiguration currentConfiguration];
    if(configuration.locationIsRequired)
    {
        //
        // Location required but the location services are not currently authorized for use
        //
        if(![MASLocationService isLocationMonitoringAuthorized])
        {
            //
            // Notify
            //
            if(completion) completion(nil, [NSError errorGeolocationServicesAreUnauthorized]);
            
            return;
        }
        
        //
        // Request the one time, currently available location before proceeding
        //
        [[MASLocationService sharedService] startSingleLocationUpdate:^(CLLocation *location, MASLocationMonitoringAccuracy accuracy, MASLocationMonitoringStatus status)
         {
             //
             // If an invalid geolocation result is detected
             //
             if((status != MASLocationMonitoringStatusSuccess && status != MASLocationMonitoringStatusTimedOut) ||
                !location)
             {
                 //
                 // Notify
                 //
                 if(completion) completion(nil, [NSError errorGeolocationIsInvalid]);
                 
                 return;
             }
             
             //
             // Update the header
             //
             NSMutableDictionary *mutableHeaderInfo = [headerInfo mutableCopy];
             mutableHeaderInfo[MASGeoLocationRequestResponseKey] = [location locationAsGeoCoordinates];
             
             //
             // create request
             //
             MASPatchURLRequest *request = [MASPatchURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:mutableHeaderInfo requestType:requestType responseType:responseType];
             
             //
             // create dataTask
             //
             NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                          completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                                  parameters:parameterInfo
                                                                                                                     headers:headerInfo
                                                                                                                  httpMethod:request.HTTPMethod
                                                                                                                 requestType:requestType
                                                                                                                responseType:responseType
                                                                                                             completionBlock:completion]];
             
             //
             // resume dataTask
             //
             [dataTask resume];
         }];
        
        return;
    }
    
    //
    // create request
    //
    MASPatchURLRequest *request = [MASPatchURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:headerInfo requestType:requestType responseType:responseType];
    
    //
    // create dataTask
    //
    NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                 completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                         parameters:parameterInfo
                                                                                                            headers:headerInfo
                                                                                                         httpMethod:request.HTTPMethod
                                                                                                        requestType:requestType
                                                                                                       responseType:responseType
                                                                                                    completionBlock:completion]];
    
    //
    // resume dataTask
    //
    [dataTask resume];
}


- (void)postTo:(NSString *)endPoint
withParameters:(NSDictionary *)parameterInfo
    andHeaders:(NSDictionary *)headerInfo
    completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Default types
    //
    [self postTo:endPoint
  withParameters:parameterInfo
      andHeaders:headerInfo
     requestType:MASRequestResponseTypeJson
    responseType:MASRequestResponseTypeJson
      completion:completion];
}


- (void)postTo:(NSString *)endPoint
withParameters:(NSDictionary *)parameterInfo
    andHeaders:(NSDictionary *)headerInfo
   requestType:(MASRequestResponseType)requestType
  responseType:(MASRequestResponseType)responseType
    completion:(MASResponseInfoErrorBlock)completion
{
    //DLog(@"called");
    //
    // Just passthrough
    //
    [self httpPostTo:endPoint
      withParameters:parameterInfo
          andHeaders:headerInfo
         requestType:requestType
        responseType:responseType
          completion:completion];
}


- (void)httpPostTo:(NSString *)endPoint
    withParameters:(NSDictionary *)parameterInfo
        andHeaders:(NSDictionary *)headerInfo
       requestType:(MASRequestResponseType)requestType
      responseType:(MASRequestResponseType)responseType
        completion:(MASResponseInfoErrorBlock)completion
{
    //DLog(@"called");
    
    //
    //  endPoint cannot be nil
    //
    if (!endPoint)
    {
        //
        // Notify
        //
        if(completion) completion(nil, [NSError errorInvalidEndpoint]);
        
        return;
    }
    
    //
    // Determine if we need to add the geo-location header value
    //
    MASConfiguration *configuration = [MASConfiguration currentConfiguration];
    if(configuration.locationIsRequired)
    {
        //
        // Location required but the location services are not currently authorized for use
        //
        if(![MASLocationService isLocationMonitoringAuthorized])
        {
            //
            // Notify
            //
            if(completion) completion(nil, [NSError errorGeolocationServicesAreUnauthorized]);
            
            return;
        }
        
        //
        // Request the one time, currently available location before proceeding
        //
        [[MASLocationService sharedService] startSingleLocationUpdate:^(CLLocation *location, MASLocationMonitoringAccuracy accuracy, MASLocationMonitoringStatus status)
         {
             //
             // If an invalid geolocation result is detected
             //
             if((status != MASLocationMonitoringStatusSuccess && status != MASLocationMonitoringStatusTimedOut) ||
                !location)
             {
                 //
                 // Notify
                 //
                 if(completion) completion(nil, [NSError errorGeolocationIsInvalid]);
                 
                 return;
             }
             
             //
             // Update the header
             //
             NSMutableDictionary *mutableHeaderInfo = [headerInfo mutableCopy];
             mutableHeaderInfo[MASGeoLocationRequestResponseKey] = [location locationAsGeoCoordinates];
             
             //
             // create request
             //
             MASPostURLRequest *request = [MASPostURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:mutableHeaderInfo requestType:requestType responseType:responseType];
             
             //
             // create dataTask
             //
             NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                          completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                                  parameters:parameterInfo
                                                                                                                     headers:headerInfo
                                                                                                                  httpMethod:request.HTTPMethod
                                                                                                                 requestType:requestType
                                                                                                                responseType:responseType
                                                                                                             completionBlock:completion]];
             
             //
             // resume dataTask
             //
             [dataTask resume];
             
         }];
        
        return;
    }
    
    //
    // create request
    //
    MASPostURLRequest *request = [MASPostURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:headerInfo requestType:requestType responseType:responseType];
    
    //
    // create dataTask
    //
    NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                 completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                         parameters:parameterInfo
                                                                                                            headers:headerInfo
                                                                                                         httpMethod:request.HTTPMethod
                                                                                                        requestType:requestType
                                                                                                       responseType:responseType
                                                                                                    completionBlock:completion]];
    
    //
    // resume dataTask
    //
    [dataTask resume];
}


- (void)putTo:(NSString *)endPoint
withParameters:(NSDictionary *)parameterInfo
   andHeaders:(NSDictionary *)headerInfo
   completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Default types
    //
    [self putTo:endPoint
 withParameters:parameterInfo
     andHeaders:headerInfo
    requestType:MASRequestResponseTypeJson
   responseType:MASRequestResponseTypeJson
     completion:completion];
}


- (void)putTo:(NSString *)endPoint
withParameters:(NSDictionary *)parameterInfo
   andHeaders:(NSDictionary *)headerInfo
  requestType:(MASRequestResponseType)requestType
 responseType:(MASRequestResponseType)responseType
   completion:(MASResponseInfoErrorBlock)completion
{
    //
    // Just passthrough
    //
    [self httpPutTo:endPoint
     withParameters:parameterInfo
         andHeaders:headerInfo
        requestType:requestType
       responseType:responseType
         completion:completion];
}


- (void)httpPutTo:(NSString *)endPoint
   withParameters:(NSDictionary *)parameterInfo
       andHeaders:(NSDictionary *)headerInfo
      requestType:(MASRequestResponseType)requestType
     responseType:(MASRequestResponseType)responseType
       completion:(MASResponseInfoErrorBlock)completion
{
    //
    //  endPoint cannot be nil
    //
    if (!endPoint)
    {
        //
        // Notify
        //
        if(completion) completion(nil, [NSError errorInvalidEndpoint]);
        
        return;
    }
    
    //
    // Determine if we need to add the geo-location header value
    //
    MASConfiguration *configuration = [MASConfiguration currentConfiguration];
    if(configuration.locationIsRequired)
    {
        //
        // Location required but the location services are not currently authorized for use
        //
        if(![MASLocationService isLocationMonitoringAuthorized])
        {
            //
            // Notify
            //
            if(completion) completion(nil, [NSError errorGeolocationServicesAreUnauthorized]);
            
            return;
        }
        
        //
        // Request the one time, currently available location before proceeding
        //
        [[MASLocationService sharedService] startSingleLocationUpdate:^(CLLocation *location, MASLocationMonitoringAccuracy accuracy, MASLocationMonitoringStatus status)
         {
             //
             // If an invalid geolocation result is detected
             //
             if((status != MASLocationMonitoringStatusSuccess && status != MASLocationMonitoringStatusTimedOut) ||
                !location)
             {
                 //
                 // Notify
                 //
                 if(completion) completion(nil, [NSError errorGeolocationIsInvalid]);
                 
                 return;
             }
             
             //
             // Update the header
             //
             NSMutableDictionary *mutableHeaderInfo = [headerInfo mutableCopy];
             mutableHeaderInfo[MASGeoLocationRequestResponseKey] = [location locationAsGeoCoordinates];
             
             //
             // create request
             //
             MASPutURLRequest *request = [MASPutURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:mutableHeaderInfo requestType:requestType responseType:responseType];
             
             //
             // create dataTask
             //
             NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                          completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                                  parameters:parameterInfo
                                                                                                                     headers:headerInfo
                                                                                                                  httpMethod:request.HTTPMethod
                                                                                                                 requestType:requestType
                                                                                                                responseType:responseType
                                                                                                             completionBlock:completion]];
             
             //
             // resume dataTask
             //
             [dataTask resume];
         }];
        
        return;
    }
    
    //
    // create request
    //
    MASPutURLRequest *request = [MASPutURLRequest requestForEndpoint:endPoint withParameters:parameterInfo andHeaders:headerInfo requestType:requestType responseType:responseType];
    
    //
    // create dataTask
    //
    NSURLSessionDataTask *dataTask = [_manager dataTaskWithRequest:request
                                                 completionHandler:[self sessionDataTaskCompletionBlockWithEndPoint:endPoint
                                                                                                         parameters:parameterInfo
                                                                                                            headers:headerInfo
                                                                                                         httpMethod:request.HTTPMethod
                                                                                                        requestType:requestType
                                                                                                       responseType:responseType
                                                                                                    completionBlock:completion]];
    
    //
    // resume dataTask
    //
    [dataTask resume];
}

@end
