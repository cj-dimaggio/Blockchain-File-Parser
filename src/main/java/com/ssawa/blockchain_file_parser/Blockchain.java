package com.ssawa.blockchain_file_parser;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.Security;
import java.util.*;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

public class Blockchain 
{
	static BufferedInputStream input;
	
	// These byte arrays will be reused throughout the parser to hold information from the file
	static byte[] oneByte = new byte[1];
	static byte[] twoByte = new byte[2];
	static byte[] fourByte = 		new byte[4];	
	static byte[] eightByte = new byte[8];
	static byte[] thirtyTwoByte = 	new byte[32];

	static ByteArrayOutputStream baos= new ByteArrayOutputStream();
	static ByteArrayOutputStream variableLengthInteger= new ByteArrayOutputStream();
	static RIPEMD160Digest ripe = new RIPEMD160Digest();

    public static void main( String[] args ) throws Exception
    {   
    	ByteArrayOutputStream output = new ByteArrayOutputStream();
    	PrintStream oldSysOut = System.out;
		//System.setOut(new PrintStream(output));
    	int count = 0;
    	File dir = new File("/Users/chardima/Library/Application Support/Bitcoin/blocks/");
    	File[] directoryListing = dir.listFiles();
		for (File child : directoryListing) {
			if (child.toString().contains("blk0")) {
				input = new BufferedInputStream(new FileInputStream(child));
				System.out.println(child.getPath());
				
		    	int eof = 0;
		    	
		    	while (eof != -1) {
			    	count++;
			    	//System.setOut(new PrintStream(output));
					eof = input.read(fourByte);
				    System.out.println("Magic Number: " + new String(Hex.encodeHex(fourByte)));
				    if (eof != -1 && !new String(Hex.encodeHex(fourByte)).equals("f9beb4d9")) {
				    	System.out.println(child.getPath());
				    	throw new Exception();
				    } else if (eof == -1) {
				    	break;
				    }
				    input.read(fourByte);
				    long size = ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
				    System.out.println("Block size: " + size);
				    
				    // Often the blocks data does not fill all of its allocated size, so we will mark this position
				    // And later when we finish parsing the data we can return to this point and jump ahead the actual size of the block to the next block header
				    input.mark((int) size);
				    baos.reset();
				    
					input.read(fourByte);
					baos.write(fourByte);
				    System.out.println("Version: " + ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong());
					
				    input.read(thirtyTwoByte);
				    baos.write(thirtyTwoByte);
				    System.out.println("Previous Block Hash: " + new String(Hex.encodeHex(thirtyTwoByte)));
				    
				    input.read(thirtyTwoByte);
				    baos.write(thirtyTwoByte);
				    System.out.println("Merkle Root Hash: " + new String(Hex.encodeHex(thirtyTwoByte)));
				    
				    input.read(fourByte);
				    baos.write(fourByte);
				    long timestamp = ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
				    System.out.println("Timestamp: " + timestamp);
				    
				    input.read(fourByte);
				    baos.write(fourByte);
				    long difficulty = java.nio.ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
				    System.out.println("Difficulty: " + difficulty);
				    
				    input.read(fourByte);
				    baos.write(fourByte);
				    long nonce = ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
				    System.out.println("Nonce: " + nonce);
				    
				    
				    System.out.println("Block Hash: " + Hex.encodeHexString(doubleHash(baos.toByteArray())));
				    
				    long numOfTxs = getVariableLengthInteger();
				    System.out.println("Number of Transactions: " + numOfTxs);
					
					// We iterate over every transaction
					for (int i=0; i < numOfTxs; i++) {
						baos.reset();
						input.read(fourByte);
						baos.write(fourByte);
					    System.out.println("\tTx Version: " + ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong());
					    
					    long numOfInputs = getVariableLengthInteger();
					    System.out.println("\tNumber of Inputs: " + numOfInputs);
					    
					    for (int y=0; y < numOfInputs; y++) {
							input.read(thirtyTwoByte);
							baos.write(thirtyTwoByte);
						    System.out.println("\t\tTransaction Hash: " + new String(Hex.encodeHex(thirtyTwoByte)));
						    
						    input.read(fourByte); 
						    baos.write(fourByte);
						    long inputIndex = ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
						    if(inputIndex == 0xFFFFFFFFl) {
						    	System.out.println("\t\tTxIndex: Newly Mined");
						    } else {
						    	System.out.println("\t\tTxIndex: " + inputIndex);
						    }
						    
						    long scriptLength = getVariableLengthInteger();
						    System.out.println("\t\tScript Length: " + scriptLength);
						    
						    // We do not need to know anything about the actual script data as we are not actually validating the block (bitcoind does that) so we skip it.
						    byte[] script = new byte[(int) scriptLength];
						    input.read(script);
						    baos.write(script);
						    
						    // We can also ignore the next 4 bytes as they are always expected to be 0xFFFFFFFF
						    input.read(fourByte);
						    baos.write(fourByte);
					    }
					    long numOfOutputs = getVariableLengthInteger();
					    System.out.println("\tNumber of Outputs: " + numOfOutputs);
					    for (int y=0; y < numOfOutputs; y++) {
					    	
					    	// The value of a transaction is in a 64 bit unsigned integer, which Java has no equivalent to (Java 7 and below)
					    	// In this case we have to switch it over to a BigInteger, which is surely a big hit in performance but there does not seem
					    	// To be a sophisticated way around it.
							input.read(eightByte);
							baos.write(eightByte);
						    System.out.println("\t\tValue: " + new BigInteger(swapEndian(eightByte)));
						    
						    long scriptLength = getVariableLengthInteger();
						    System.out.println("\t\tScript Length: " + scriptLength);
						    
						    byte[] script = new byte[(int) scriptLength];
						    input.read(script);
						    baos.write(script);
						    System.out.println("\t\t" + getPublicAddress(script));
					    }
					    // The next bit is the transaction lock time, which is currently always zero. We can skip it.
					    input.read(fourByte);
					    baos.write(fourByte);
					    
					    System.out.println("\tTransaction Hash: " + Hex.encodeHexString(doubleHash(baos.toByteArray())));
					}
					
				    // Reset to the beginning of block and skip the size of the block to get to the next
				    input.reset();
				    safeSkip(size);
				    
					/*output.reset();
					System.setOut(oldSysOut);
					System.out.println(count);*/
		    	}
			    
		    	input.close();
			}
		}
    }
    
    static protected byte[] doubleHash(byte[] bytes) throws Exception {
    	// Get the double hash of byte array. This gets us things like the block hash and the transaction hash
    	byte[] hash;
    	MessageDigest sha = MessageDigest.getInstance("SHA-256");
    	sha.update(bytes);
    	hash = sha.digest();
    	sha.update(hash);
    	return sha.digest();
    }
    
    // Sometimes a BufferedInputStream will skip for less bytes than was asked. To safeguard this we have to check to make sure the proper amount was skipped and if not, skip again
    static protected void safeSkip(long num) throws Exception{
    	long actual = 0;
    	while(actual != num) {
    		num -= actual;
    		actual = input.skip(num);
    	}
    }
    
    // The public key will be saved as part of the output script (indicating that the transaction can be used when signed by the corresponding public key
    // While a custom output script can be used, these are generally by default not accepted by miners. There are currently only a handful of accepted scripts
    // Which we parse for and decode in this function based on the script length. In the future we might be able to implement a full script interpreter
    static protected String getPublicAddress(byte[] script) throws Exception{
    	
    	// If these conditions are met than the public address is a 65 byte key.
    	// Note that the final final byte of the script should be 0xAC which java overflows to -84 because of the signed/unsigned problem
    	if (script.length == 67 && script[0] == 65 && script[66] == -84) {
    		return publicKeyToAddress(Arrays.copyOfRange(script, 1, 66));
    	} else if (script.length == 66 && script[65] == -84) {
    		// Same as the one above except the length field of the first byte is missing (This does not show up often in the block chain)
    		return publicKeyToAddress(Arrays.copyOfRange(script, 1, 66));
    	} else if (script.length == 25 && script[0] == 0x76 && script[1] == -87 && script[2] == 20) {
    		// Note that the 2nd byte should be equal to 0xA9 but java overflows this to -87
    		// This is the most common type of script and will be encountered most often
    		return new String(Hex.encodeHex(Arrays.copyOfRange(script, 3, 23)));
    	} else if (script.length == 5 && script[0] == 0x76 && script[1] == -87 && script[2] == 0 && script[3] == 0x88 && script[4] == -84) {
    		// This signifies a transaction with no address. It is usually done in error but does appear in the block chain
    		return "No Address";
    	} else if (script.length > 25 && script[0] == 0x76 && script[1] == -87 && script[2] == 20 && script[23] == 0x88 && script[24] == -84) {
    		return new String(Hex.encodeHex(Arrays.copyOfRange(script, 3, 23)));
    	} else {
    		return "Public Address can't be deduced from script";
    	}
    }
    
    // In some cases an output will only point to a 65 byte public key as opposed to the base-58 ASCII 20 byte address most people are familiar with
    static protected String publicKeyToAddress(byte[] key) throws Exception {
		byte[] addressBinary = new byte[25];
		byte[] firstHash;
		
		// Because we are using the main network we set the first byte of the address hash to "0" for 'main'
		addressBinary[0] = 0;
		// Perform a sha-256 hash of the public key
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		sha.update(key);
		firstHash = sha.digest();
		// Compute a 20 byte RIPEMD-160 hash of the sha-256 hash
		ripe.update(firstHash, 0, 32);
		ripe.doFinal(addressBinary, 1);
		// Now we need to do some more sha-256 hashes to get a checksum for the address
		sha.update(addressBinary, 0, 21);
		firstHash = sha.digest();
		sha.update(firstHash);
		firstHash = sha.digest();
		addressBinary[21] = firstHash[0];
		addressBinary[22] = firstHash[1];
		addressBinary[23] = firstHash[2];
		addressBinary[24] = firstHash[3];
		
		// Now we encode the binary into a base58 ASCII string
    	return Base58.encode(addressBinary);
    }
    
    // BigInteger uses large endianness where as the bitcoin protocol saves things as little, so we must swap it sometimes
    static protected byte[] swapEndian(byte[] original) {
    	byte[] swapped = new byte[8];
    	for (int i=0; i < original.length; i++) {
    		swapped[i] = original[original.length -1 - i];
    	}
    	return swapped;
    }
    
	// Bitcoin uses a variable length integer format for saving the number of transactions (see https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer for explanation)
    static protected long getVariableLengthInteger() throws Exception{
    	int test = input.read(oneByte);
		baos.write(oneByte);

		int firstVLIByte = (oneByte[0] & 0xFF);
		if((oneByte[0] & 0xFF) < 0xFD) {
			
			// If the first byte is less then 0xFD we use that first byte
			return (long) (oneByte[0] & 0xFF);
		} else if (firstVLIByte == 0xFD) {
			
			// If the first byte equals 0xFD then we use the following two bytes
			baos.write(twoByte);
			input.read(twoByte);
			return ByteBuffer.wrap(padForLong(twoByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
		} else if (firstVLIByte == 0xFE) {
			
			// If the first byte equals 0xFE then we use the following four bytes
			baos.write(fourByte);
			input.read(fourByte);
			return ByteBuffer.wrap(padForLong(fourByte)).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
		} else {
			
			// Finally, if the first equals 0xFF we use the following eight bytes.
			// It's very important to note that java longs are signed,
			// if the number of transactions of this category reaches a certain threshold (about half of total capacity)
			// the number will be negative as far as java is concerned. It is incredibly unlikely that this number
			// will be reached in one block but it should still be handled at some point.
			baos.write(eightByte);
			input.read(eightByte);
			return ByteBuffer.wrap(eightByte).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
		}
    }
    
    // Because all numerical primitives in java are strictly signed (for Java 7 and under)
    // We must convert the bytes into a long so that large numbers do not overflow into negatives
    static protected byte[] padForLong(byte[] original) {
    	byte[] padded = new byte[8];
    	for (int i=0; i < padded.length; i++) {
    		if (i < original.length) {
    			padded[i] = original[i];
    		} else {
    			padded[i] = 0x00;
    		}
    	}
    	return padded;
    }
}
