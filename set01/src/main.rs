use std::io::prelude::*;
use std::fs::File;
use regex::Regex;
use std::path::PathBuf;
use openssl::symm::{decrypt, Cipher};
use std::collections::HashSet;

// https://docs.rs/openssl/0.10.28/openssl/
// ssl dev libraries needed: apt install pkg-config libssl-dev

/// Set 1, Challenge 1. Converts hexadecimals to bytes and encodes the result to base64
///
/// # Arguments
///
/// * `hex_str` - Hexadecimal string
///
/// # Example
///
/// ```
/// let base64_encoded_value = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").expect("error")
/// ```
pub fn hex_to_base64(hex_str : &str) -> Result<String, &'static str> {
    let decoded_bytes = match hex::decode(hex_str.trim()) {
        Result::Ok(val) => val,
        Result::Err(_) => return Err("Invalid input received")
    };

    Ok(base64::encode(decoded_bytes).to_owned())
}

/// Set 1, Challenge 2. Fixed XOR and Set 1, Challenge 5. Implement repeating-key XOR
pub fn fixed_xor(hex_str : &str, xor_str : &str) -> Result<String, &'static str> {
    let mut decoded_input_bytes = match hex::decode(hex_str.trim()) {
        Result::Ok(val) => val,
        Result::Err(_) => return Err("Invalid HEX input received")
    };

    let decoded_xor_bytes = match hex::decode(xor_str.trim()) {
        Result::Ok(val) => val,
        Result::Err(_) => return Err("Invalid XOR input received")
    };

    for i in 0..decoded_input_bytes.len() {
        decoded_input_bytes[i] = decoded_input_bytes[i] ^ decoded_xor_bytes[i % decoded_xor_bytes.len()];
    }

    Ok(hex::encode(decoded_input_bytes).to_owned())
}

/// Attempt to qualify character to find statistically more relevant strings in brute_forced string
/// I.e. prefer US alphabet over any other characters, give worse score to control characters and rarer characters.
/// To make it better this could make sense: http://norvig.com/mayzner.html
fn calculate_byte_validity(mut byte : u8) -> (u8, f64) {
    let mut validity : f64;

    const ASCII_SPACE : u8 = 32;
    const ASCII_DOLLAR : u8 = 36;
    const ASCII_A_UPPER : u8 = 65;
    const ASCII_Z_UPPER : u8 = 90;
    const ASCII_A_LOWER : u8 = 97;
    const ASCII_Z_LOWER : u8 = 126;

    if byte < ASCII_SPACE || byte > ASCII_Z_LOWER {
        validity = -0.1;

        byte = ASCII_DOLLAR;
    } else {
        validity = 0.2;

        if byte >= ASCII_A_UPPER && byte <= ASCII_Z_UPPER {
            validity = 1.0;
        } else if byte >= ASCII_A_LOWER && byte <= ASCII_Z_LOWER {
            validity = 1.0;
        } else if byte == ASCII_SPACE {
            validity = 0.8;
        }
    }

    (byte, validity)
}

pub fn single_byte_xor(hex_str : &str, byte_cipher : u8) -> Result<(String, f64, u8), &'static str> {
    let mut decoded_input_bytes = match hex::decode(hex_str.trim()) {
        Result::Ok(val) => val,
        Result::Err(_) => return Err("Invalid HEX input received")
    };

    let mut total_validity : f64 = 0.0;
    for i in 0..decoded_input_bytes.len() {
        let decoded_byte : u8 = decoded_input_bytes[i] ^ byte_cipher;

        let (validated_byte, validity) = calculate_byte_validity(decoded_byte);
        decoded_input_bytes[i] = validated_byte;

        total_validity = total_validity + validity;
    }

    let percent = total_validity / decoded_input_bytes.len() as f64;
    Ok((String::from_utf8(decoded_input_bytes).unwrap().to_owned(), percent, byte_cipher))
}

/// Set 1, Challenge 3. Single-byte XOR cipher brute force
pub fn brute_force_single_byte_xor(hex_str : &str) -> Result<(String, f64, u8), &'static str> {
    let mut best_result = (String::new(), std::f64::MIN, 0);

    for i in 0x00..0xFF {
        let latest_result = single_byte_xor(hex_str, i).expect("something went wonky");
        //println!("{} -> {},{}:{}", i, latest_result.2, latest_result.1, latest_result.0);

        if best_result.1 < latest_result.1 {
            best_result = latest_result;
        }
    }

    Ok(best_result)
}

fn read_file_to_string(file : &str, buffer : &mut String) {
    let mut file_absolute_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_absolute_path.push("resources/");
    file_absolute_path.push(file);

    let mut f = File::open(file_absolute_path).expect("could not open file!");
    
    f.read_to_string(buffer).expect("could not read file!");
}

/// Set 1, Challenge 4. Detect single-character XOR from a file
pub fn brute_force_xor_decrypt_string_from_file(file : &str) -> Result<(String, f64, u8), &'static str> {
    let mut buffer = String::new();
    read_file_to_string(file, &mut buffer);

    let re = Regex::new(r"\s+").unwrap();
    let rows: Vec<&str> = re.split(&buffer).collect();

    let mut best_result = (String::new(), std::f64::MIN, 0);
    for row in rows {
        let latest_result = brute_force_single_byte_xor(row).expect("something went wonky");

        if best_result.1 < latest_result.1 {
            best_result = latest_result;
        }        
    }

    Ok(best_result)
}

/// Set 1, Challenge 6. Break repeating-key XOR
macro_rules! get_bit {
    ($byte:expr, $bit:expr) => (if $byte & (1 << $bit) != 0 { 1 } else { 0 });
}

pub fn calculate_hamming_distance(arg1 : &[u8], arg2 : &[u8], size : usize) -> u64 {
    if size > arg1.len() {
        panic!("Input strings are smaller than size! '{}' < '{}'", arg1.len(), size);
    }
    else if size > arg2.len() {
        panic!("Input strings are smaller than size! '{}' < '{}'", arg2.len(), size);
    }

    let mut result : u64 = 0;

    for i in 0..size {
        let c1 = arg1[i];
        let c2 = arg2[i];

        for b in (0..8).rev() {
            let bit1 : u8 = get_bit!(c1, b);
            let bit2 : u8 = get_bit!(c2, b);
            
            if bit1 != bit2 {
                result = result + 1;
            }
        }
    }

    result
}

/// determine the like
fn determine_key_size(encrypted_data : &[u8], key_size_min : usize, key_size_max : usize) -> usize {
    assert!(key_size_min <= key_size_max, "key_size_min:{} greater than key_size_max:{}", key_size_min, key_size_max);
    assert!(encrypted_data.len() >= key_size_max*2, "encrypted_data.len():{} less than key_size_max*2:{}", encrypted_data.len(), key_size_max*2);

    //  For each KEYSIZE
    //  take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and
    //  find the edit distance between them. Normalize this result by dividing by KEYSIZE. 

    let mut probable_key_size : usize = 0;
    let mut smallest_edit_distance : f64 = std::f64::MAX;

    for key_size in key_size_min..key_size_max {

        let mut normalized_edit_distance : f64 = 0.0;
        for encrypted_data_i in (0..key_size * (encrypted_data.len() / key_size_max - 1)).step_by(key_size) {
            let sample1 = &encrypted_data[encrypted_data_i..encrypted_data_i+key_size];
            let sample2 = &encrypted_data[encrypted_data_i+key_size..encrypted_data_i+key_size*2];
            let edit_distance = calculate_hamming_distance(sample1, sample2, key_size);

            normalized_edit_distance = normalized_edit_distance + edit_distance as f64 / key_size as f64;
        }

        if normalized_edit_distance <= smallest_edit_distance {
            probable_key_size = key_size;
            smallest_edit_distance = normalized_edit_distance;
        }
    }

    probable_key_size
} 

pub fn break_repeating_key_xor(probable_key_size : usize, encrypted_data : Vec<u8>) -> (String, String) {

    const KEY_SIZE_MAX : usize = 40;
    assert!(probable_key_size <= KEY_SIZE_MAX, "Key size larger than maximum! {} <= {}", probable_key_size, KEY_SIZE_MAX);

    let mut key_slot_blocks: Vec<Vec<u8>> = Vec::with_capacity(probable_key_size);
    for _ in 0..probable_key_size {
        key_slot_blocks.push(Vec::with_capacity(encrypted_data.len() / probable_key_size));
    }

    for key_step in (0..encrypted_data.len()).step_by(probable_key_size) {
        let mut encrypted_data_block = [0; KEY_SIZE_MAX];

        let mut copy_size = probable_key_size;
        if key_step+copy_size >= encrypted_data.len() {
            copy_size = encrypted_data.len() - key_step;
        }
        encrypted_data_block[..copy_size].clone_from_slice(&encrypted_data[key_step..key_step+copy_size]);

        //  Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on. 
        for key_slot_index in 0..probable_key_size {
            key_slot_blocks[key_slot_index].push(encrypted_data_block[key_slot_index]);
        }
    }

    //  Solve each block as if it was single-character XOR. You already have code to do this. 
    let mut solved_key: Vec<u8> = Vec::with_capacity(probable_key_size);

    for i in 0..key_slot_blocks.len() {
        let key_slot_block = &key_slot_blocks[i];
        let encoded_cipher_data = &hex::encode(&key_slot_block[..]);
        //  For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key. 
        let (_, _, byte) = brute_force_single_byte_xor(encoded_cipher_data).expect("xor decoding issue");
        solved_key.push(byte);
    }

    let solved_key_hex = hex::encode(&solved_key[..]);

    let decrypted_output = fixed_xor(&hex::encode(encrypted_data), &solved_key_hex).expect("xor decrypt failed");

    (decrypted_output, solved_key_hex)
}

pub fn brute_force_repeating_key_xor() -> (usize, String, String) {
    let mut buffer = String::new();
    read_file_to_string("6.txt", &mut buffer);
    
    //base64 crate's decode doesn't allow whitespaces
    buffer.retain(|c| !" \n".contains(c));
    let encrypted_data = base64::decode(buffer).expect("could not decode base64");

    //  Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40. 
    const KEY_SIZE_MIN : usize = 2;
    const KEY_SIZE_MAX : usize = 40;

    //  The KEYSIZE with the smallest normalized edit distance is probably the key.
    //  You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    let probable_key_size = determine_key_size(&encrypted_data[..], KEY_SIZE_MIN, KEY_SIZE_MAX);

    //  Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length. 
    let (decrypted_output, solved_key_hex) = break_repeating_key_xor(probable_key_size, encrypted_data);

    (probable_key_size, decrypted_output, solved_key_hex)
}

/// Set 1, Challenge 7. AES in ECB mode
pub fn decrypt_aes_128_ecb() -> String {
    let mut buffer = String::new();
    read_file_to_string("7.txt", &mut buffer);

    //base64 crate's decode doesn't allow whitespaces
    buffer.retain(|c| !" \n".contains(c));
    let encrypted_data = base64::decode(buffer).expect("could not decode base64");

    let key = "YELLOW SUBMARINE";
    let cipher = Cipher::aes_128_ecb();

    let cipher_text = decrypt(cipher, key.as_bytes(), None, &encrypted_data[..]).unwrap();

    String::from_utf8(cipher_text).unwrap()
}

/// Set 1, Challenge 8. Detect AES in ECB mode
pub fn detect_aes_in_ecb() -> (f64, String) {
    let mut buffer = String::new();
    read_file_to_string("8.txt", &mut buffer);

    let re = Regex::new(r"\s+").unwrap();
    let rows: Vec<&str> = re.split(&buffer).collect();

    let mut best_result = (std::f64::MIN, String::new());

    for i in 0..rows.len() {
        let row = rows[i];
        if row.len() == 0 {
            continue;
        }

        let row = hex::decode(row).expect("hex decode failed");
        const BLOCK_LENGTH : usize = 128/8;

        assert!(row.len()%BLOCK_LENGTH == 0, "row length not dividable by {}! len:{}", BLOCK_LENGTH, row.len());

        //  Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext. 
        let mut unique_blocks = HashSet::new();

        for block_index in (0..row.len()).step_by(BLOCK_LENGTH) {
            let block1 = &row[block_index..block_index+BLOCK_LENGTH];
            unique_blocks.insert(block1);
        }

        let score : f64 = 1.0 - unique_blocks.len() as f64 / (row.len() / BLOCK_LENGTH) as f64;

        if best_result.0 <= score {
            best_result = (score, hex::encode(row));
        }
    }

    best_result
}

/// The program's actual entry-point is the test suite instead of main function, so run: cargo test
fn main() {
    panic!("To execute/verify run the unit tests: cargo test");
}

#[cfg(test)]
mod challenges {
    use super::*;

    #[test]
    fn test_challenge01_success() -> Result<(), String> {
        assert_eq!(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hex_to_base64("deaDBEef  \n")?, "3q2+7w==");
        Ok(())
    }
    #[test]
    fn test_challenge01_invalid_input() {
        let result = hex_to_base64("this is definitely not hexadecimal string");
        assert_eq!(result, Err("Invalid input received"));
    }

    #[test]
    fn test_challenge02_success() -> Result<(), String> {
        assert_eq!(fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")?, "746865206b696420646f6e277420706c6179");
        assert_eq!(fixed_xor("deadbeef", "1337")?, "cd9aadd8");
        Ok(())
    }

    #[test]
    fn test_challenge03_success() {
        let (output, percent, _) = brute_force_single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").expect("could not brute force");

        assert_eq!(output, "Cooking MC's like a pound of bacon");
        assert_eq!(percent >= 0.90, true);
    }

    #[test]
    fn test_challenge04_success() {
        let (output, percent, _) = brute_force_xor_decrypt_string_from_file("4.txt").expect("could not brute force");

        assert_eq!(output, "Now that the party is jumping$");
        assert_eq!(percent >= 0.90, true);
    }

    #[test]
    fn test_challenge05_success() -> Result<(), String> {
        let original_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = "ICE";
        let encrypted_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        assert_eq!(fixed_xor(&hex::encode(original_text), &hex::encode(key))?, encrypted_output);
        assert_eq!(fixed_xor(encrypted_output, &hex::encode(key))?, hex::encode(original_text));
        Ok(())
    }

    #[test]
    fn test_challenge06_hamming_distance() {
        let arg1 = "this is a test".as_bytes();
        let arg2 = "wokka wokka!!!".as_bytes();

        assert_eq!(calculate_hamming_distance(arg1, arg2, arg1.len()), 37);
        assert_eq!(calculate_hamming_distance(arg2, arg1, arg2.len()), 37);

        assert_eq!(calculate_hamming_distance(arg1, arg1, arg1.len()), 0);

        assert_eq!(calculate_hamming_distance("b".as_bytes(), "c".as_bytes(), 1), 1);
    }

    #[test]
    fn test_challenge06_key_distance() -> Result<(), String> {
        let encrypted_data = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let encrypted_data = hex::decode(encrypted_data).expect("hex decode failed");
        let key = "ICE";

        const KEY_SIZE_MIN : usize = 2;
        const KEY_SIZE_MAX : usize = 30;
        let probable_key_size = determine_key_size(&encrypted_data[..], KEY_SIZE_MIN, KEY_SIZE_MAX);

        // In theory small key's best guess distance should be calculated using modulo?
        assert_eq!(probable_key_size%key.len(), 0);

        let unencrypted_text = "Kaikenlaista paskaa koodia tassa kirjoitellaan. Ongelmana on monesti, etta asiat ja algoritmit eivat mene niin kuin Stromsossa on tapana menna 2020-luvulla!";
        let hex_key = "AA1337DEADBEEF00112233445566";
        let encrypted_data = hex::decode(fixed_xor(&hex::encode(unencrypted_text), &hex_key)?).expect("hex decode failed");
        let probable_key_size = determine_key_size(&encrypted_data[..], KEY_SIZE_MIN, KEY_SIZE_MAX);
        assert_eq!(probable_key_size, hex_key.len()/2);

        assert_ne!((hex_key.len()/2) % key.len(), 0);

        Ok(())
    }

    #[test]
    fn test_challenge06_success() {
        let correct_key = "Terminator X: Bring the noise";

        let (probable_key_size, decrypted_output, solved_key_hex) = brute_force_repeating_key_xor();

        assert_eq!(String::from_utf8(hex::decode(solved_key_hex).expect("hex decode failed")).unwrap(), correct_key);
        assert_eq!(probable_key_size, correct_key.len());
        assert_eq!(decrypted_output.len() > 10, true);
    }

    #[test]
    fn test_challenge07_success() {
        let cipher_text = decrypt_aes_128_ecb();
        assert_eq!(cipher_text.find("Play that funky music"), Some(2471));
    }

    #[test]
    fn test_challenge08_success() {
        let result = detect_aes_in_ecb();
        assert_eq!(result.0 > 0.0, true);
        assert_eq!(result.1.find("08649af70dc06f4fd5d2d69c744cd283"), Some(32));
    }
}
