//
//  DUKPT.m
//  POS
//
//  Created by Mikhail Burshteyn on 12/27/12.
//  Copyright (c) 2012 Southern Company. All rights reserved.
//

#import "DUKPT.h"
#import "CommonCryptor.h"

@implementation DUKPT

@synthesize BDK;
@synthesize KSN;

NSData* register1;
NSData* register2;

NSData* keyLeft;
NSData* keyRight;

NSData* ksnData;

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

- (id)initWithBDK:(NSString *)bdk KSN:(NSString *)ksn
{
    self = [super init];
    if (self)
    {
        self.BDK = bdk;
        self.KSN = ksn;
        
        ksnData = [self dataFromString:KSN];
        
        [self getIPEK];
        
        uint32_t rollingCounter = 0;
        uint32_t counterKey = [self getCounter];
        
        for (int x = 21; x>=0; x--) {
            uint32_t power = powl(2, x);
            if ((counterKey & power) > 0)
            {
                rollingCounter += (counterKey & power);
                NSData* counter = [self setCounter:rollingCounter];
                register1 = [counter subdataWithRange:NSMakeRange(2, 8)];
                
                [self keyGen];
            }
        }
        
        [self variantKeys];
    }
    
    return self;
}

- (void)getIPEK
{
    NSData* ksn = [self clearCounter];
    NSData* firstBlock = [self DESOperation:kCCEncrypt algorithm:kCCAlgorithm3DES keySize:kCCKeySize3DES data:ksn key:[self dataFromString:BDK]];
    
    keyLeft = firstBlock;
    
    NSData* xorKey = [self xorData:[self dataFromString:BDK] withData:[self dataFromString:@"C0C0C0C000000000C0C0C0C000000000"]];
    NSData* secondBlock = [self DESOperation:kCCEncrypt algorithm:kCCAlgorithm3DES keySize:kCCKeySize3DES data:ksn key:xorKey];
    
    keyRight = secondBlock;
}

- (NSData*)dataFromString:(NSString*)string
{
    NSMutableData* result = [NSMutableData dataWithCapacity: string.length / 2];
    
    for (int i = 0; i < [string length] - 1; i += 2) {
        unsigned int anInt;
        NSString * hexCharStr = [string substringWithRange:NSMakeRange(i, 2)];
        NSScanner * scanner = [[NSScanner alloc] initWithString:hexCharStr];
        [scanner scanHexInt:&anInt];
        [result appendBytes:&anInt length:1];
    }
    return [NSData dataWithBytes:[result bytes] length:[result length]];
}

- (NSData*)DESOperation:(CCOperation)operation algorithm:(CCAlgorithm)algorithm keySize:(size_t)keySize data:(NSData*)data key:(NSData*)key
{
    NSMutableData* alterKey = [NSMutableData dataWithData:key];
    [alterKey appendData:[key subdataWithRange:NSMakeRange(0, 8)]];
    
    size_t movedBytes = 0;
    const void* plainText = [data bytes];
    size_t plainTextBufferSize = [data length];
    
    size_t bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    
    uint8_t *bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *ptrKey = [alterKey bytes];
    
    CCCryptorStatus ccStatus = CCCrypt(operation, algorithm, kCCOptionECBMode, (const void *)ptrKey, keySize, NULL, (const void *)plainText, plainTextBufferSize, (void *)bufferPtr, bufferPtrSize, &movedBytes);
    
    if (ccStatus == kCCParamError) NSLog(@"PARAM ERROR");
    else if (ccStatus == kCCBufferTooSmall) NSLog(@"BUFFER TOO SMALL");
    else if (ccStatus == kCCMemoryFailure) NSLog(@"MEMORY FAILURE");
    else if (ccStatus == kCCAlignmentError) NSLog(@"ALIGNMENT");
    else if (ccStatus == kCCDecodeError) NSLog(@"DECODE ERROR");
    else if (ccStatus == kCCUnimplemented) NSLog(@"UNIMPLEMENTED");
    
    
    NSData* result = [NSData dataWithBytes:bufferPtr length:movedBytes];
    return result;
    
}

- (NSData*)clearCounter
{
    NSData* dataAnd = [self dataFromString:@"FFFFFFFFFFE00000"];
    NSData* dataKSN = [self dataFromString:[KSN substringFromIndex:4]];
    
    uint64_t intAnd = 0;
    [dataAnd getBytes:&intAnd];
    
    uint64_t intKSN = 0;
    [dataKSN getBytes:&intKSN];
    
    uint64_t intResult = 0;
    intResult = intKSN & intAnd;
    
    NSMutableData* result = [NSMutableData dataWithData:[ksnData subdataWithRange:NSMakeRange(0, 2)]];
    [result appendData:[NSData dataWithBytes:&intResult length:8]];
    return result;
    
}

- (uint32_t)getCounter
{
    NSData* dataAnd = [self dataFromString:@"00000000001FFFFF"];
    NSData* dataKSN = [self dataFromString:[KSN substringFromIndex:4]];
    
    uint64_t intAnd = 0;
    [dataAnd getBytes:&intAnd];
    
    uint64_t intKSN = 0;
    [dataKSN getBytes:&intKSN];
    
    uint64_t intResult = 0;
    intResult = intKSN & intAnd;
    intResult = CFSwapInt64(intResult);
    return intResult;
}

- (NSData*)setCounter:(uint32_t)counter
{
    NSData* cleanKSN = [[self clearCounter] subdataWithRange:NSMakeRange(6, 4)];
    
    uint32_t right = 0;
    
    [cleanKSN getBytes:&right];
    right+=CFSwapInt32(counter);
    NSMutableData* resultData = [NSMutableData dataWithData:[ksnData subdataWithRange:NSMakeRange(0, 6)]];
    [resultData appendBytes:&right length:4];
    return resultData;
}

- (NSData*)xorData:(NSData*)data withData:(NSData*)xorValue
{
    NSMutableData* result = [[NSMutableData alloc] init];
    
    for (int x = 0; x < data.length / 8; x++) {
        
        uint64_t intXor = 0;
        [[xorValue subdataWithRange:NSMakeRange(x * 8, 8)] getBytes:&intXor];
        
        uint64_t intData = 0;
        [[data subdataWithRange:NSMakeRange(x * 8, 8)] getBytes:&intData];
        
        uint64_t intResult = 0;
        intResult = intData ^ intXor;
        
        [result appendBytes:&intResult length:8];
    }
    return result;
}

- (void)keyGen
{
    uint64_t _register1 = 0;
    [register1 getBytes:&_register1];
    
    uint64_t _keyRight = 0;
    [keyRight getBytes:&_keyRight];
    
    uint64_t _keyLeft = 0;
    [keyLeft getBytes:&_keyLeft];
    
    uint64_t _register2 = _register1 ^ _keyRight;
    register2 = [NSData dataWithBytes:&_register2 length:8];
    register2 = [self DESOperation:kCCEncrypt algorithm:kCCAlgorithmDES keySize:kCCKeySizeDES data:register2 key:[NSData dataWithBytes:&_keyLeft length:8]];
    
    [register2 getBytes:&_register2];
    _register2 ^= _keyRight;
    register2 = [NSData dataWithBytes:&_register2 length:8];
    
    uint64_t _xor1 = 0;
    [[self dataFromString:@"C0C0C0C000000000"] getBytes:&_xor1];
    
    uint64_t _xor2 = 0;
    [[self dataFromString:@"C0C0C0C000000000"] getBytes:&_xor2];
    
    _keyLeft ^= _xor1;
    _keyRight ^= _xor2;
    
    _register1 ^= _keyRight;
    
    register1 = [self DESOperation:kCCEncrypt algorithm:kCCAlgorithmDES keySize:kCCKeySizeDES data:[NSData dataWithBytes:&_register1 length:8] key:[NSData dataWithBytes:&_keyLeft length:8]];
    [register1 getBytes:&_register1];
    _register1 ^= _keyRight;
    register1 = [NSData dataWithBytes:&_register1 length:8];
    
    keyLeft = register1;
    keyRight = register2;
    
    NSLog(@"%@ %@", register1, register2);
    
    
}

- (void)variantKeys
{
    NSData* dataXor = [self dataFromString:@"00000000000000FF"];
    
    uint64_t intXor = 0;
    [dataXor getBytes:&intXor];
    
    uint64_t intKey = 0;
    [keyLeft getBytes:&intKey];
    
    uint64_t intResult = 0;
    intResult = intKey ^ intXor;
    keyLeft = [NSData dataWithBytes:&intResult length:8];
    
    intKey = 0;
    [keyRight getBytes:&intKey];
    
    intResult = 0;
    intResult = intKey ^ intXor;
    keyRight = [NSData dataWithBytes:&intResult length:8];
}

- (NSString*)decrypt:(NSString*)data
{
    NSMutableString* result = [[NSMutableString alloc]init];
    
    for (int x = data.length - 16; x >= 0; x -= 16) {
        NSString* block = [data substringWithRange:NSMakeRange(x, 16)];
        NSMutableData* key  = [NSMutableData dataWithData:keyLeft];
        [key appendData:keyRight];
        NSData* decryptedBlock = [self DESOperation:kCCDecrypt algorithm:kCCAlgorithm3DES keySize:kCCKeySize3DES data:[self dataFromString:block] key:key];
        
        if (x > 0)
        {
            NSString* blockPrev = [data substringWithRange:NSMakeRange(x - 16, 16)];
            decryptedBlock = [self xorData:decryptedBlock withData:[self dataFromString:blockPrev]];
        }
        NSString *myString = [[NSString alloc] initWithData:decryptedBlock encoding:NSUTF8StringEncoding];
        [result insertString:myString atIndex:0];
    }
    return result;
}

@end
