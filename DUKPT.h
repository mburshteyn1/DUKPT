//
//  DUKPT.h
//  POS
//
//  Created by Mikhail Burshteyn on 12/27/12.
//  Copyright (c) 2012 Southern Company. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DUKPT : NSObject

@property NSString* BDK;
@property NSString* KSN;

- (id)initWithBDK:(NSString*)bdk KSN:(NSString*)ksn;

- (NSString*)decrypt:(NSString*)data;

@end
