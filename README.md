DUKPT
=====

This code was written to decrypt transactions coming from the MagTek iDynamo iOS devices.  It should work with other credit card devices using the DUKPT algorithm to encrypt data.  In order to use the function you must have access to the Base Derivation Key (BDK) with which your iDynamo (or another device) was encoded.  

### Usage:

<pre><code>DUKPT* d = [[DUKPT alloc]initWithBDK:@"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" KSN:[mtSCRALib getKSN]];
NSLog([d decrypt:[mtSCRALib getTrack1]]);
</code></pre>


This initializes the DUKPT class using the BDK obtained from the device provider, and the transaction KSN from the device.  The decrypt method takes in the encrypted track and returns the decrypted string.  
