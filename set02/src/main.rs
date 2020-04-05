/// Set 2, Challenge 9. Implement PKCS#7 padding
/// 
/// # Examples
/// 
/// ```should_panic
/// let result = pkcs7_pad(&[0,1,2], 8);
/// assert_eq!(result, &[0,1,2,4,4,4,4,4,5]);
/// ```
pub fn pkcs7_pad(data : &[u8], block_size : usize) -> Vec<u8> {
    const PAD_BYTE : u8 = 0x04;
    let mut vec : Vec<u8> = Vec::new();
    vec.extend_from_slice(data);

    let pad_size = block_size - (data.len()%block_size);

    if pad_size < block_size {
        for _ in 0..pad_size {
            vec.push(PAD_BYTE);
        }
    }

    vec
}

/// The program's actual entry-point is the test suite instead of main function, so run: cargo test
fn main() {
    panic!("To execute/verify run the unit tests: cargo test");
}

#[cfg(test)]
mod challenges {
    use super::*;

    #[test]
    fn test_challenge09_pcks7_padding() -> Result<(), String> {
        let text = "YELLOW SUBMARINE";
        let result = pkcs7_pad(&text.as_bytes(), 20);
        assert_eq!(result, &[89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4]);

        let result = pkcs7_pad(&[0,1,2], 8);
        assert_eq!(result, &[0,1,2,4,4,4,4,4]);

        let result = pkcs7_pad(&[3,1,3], 3);
        assert_eq!(result, &[3,1,3]);

        let result = pkcs7_pad(&[6,5,4], 1);
        assert_eq!(result, &[6,5,4]);

        Ok(())
    }
}
