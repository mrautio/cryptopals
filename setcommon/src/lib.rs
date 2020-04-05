
#[macro_export]
macro_rules! get_bit {
    ($byte:expr, $bit:expr) => (if $byte & (1 << $bit) != 0 { 1 } else { 0 });
}

pub mod io {
    use regex::Regex;
    use std::io::prelude::*;
    use std::fs::File;
    use std::path::PathBuf;

    pub fn open_file(file : &str) -> File {
        let mut file_absolute_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file_absolute_path.push("resources/");
        file_absolute_path.push(file);

        File::open(file_absolute_path).expect("could not open file!")
    }

    pub fn read_file_to_string(file : &str) -> String {
        let mut f = open_file(file);

        let mut buffer = String::new();
        f.read_to_string(&mut buffer).expect("could not read file!");

        buffer
    }

    pub fn base64_decode(buffer : &mut String) -> Vec<u8> {
        //base64 crate's decode doesn't allow whitespaces
        buffer.retain(|c| !" \n\r\t".contains(c));
        let decoded_data = base64::decode(buffer).expect("could not decode base64");

        decoded_data
    }

    pub fn split_whitespace(buffer : &str) -> Vec<&str> {
        let buffer = buffer.trim();
        let re = Regex::new(r"\s+").unwrap();
        let rows: Vec<&str> = re.split(&buffer).collect();

        rows
    }
}

#[cfg(test)]
mod tests {
    use std::io::prelude::*;
    use super::io::*;

    #[test]
    fn test_open_file() -> Result<(), String> {
        let mut f = open_file("test.md");

        let mut buffer = String::new();
        f.read_to_string(&mut buffer).expect("could not read file");

        assert_eq!(buffer, "This file is just for test purposes");

        Ok(())
    }

    #[test]
    fn test_read_file_to_string() -> Result<(), String> {
        let buffer = read_file_to_string("test.md");

        assert_eq!(buffer, "This file is just for test purposes");

        Ok(())
    }

    #[test]
    fn test_base64_decode() -> Result<(), String> {
        let mut encoded_data = "VEhJUy  BJUy\tBBI\rFNU\n\nUklORw==".to_string();

        let decoded_data = base64_decode(&mut encoded_data);

        assert_eq!(String::from_utf8(decoded_data).unwrap(), "THIS IS A STRING");

        Ok(())
    }

    #[test]
    fn test_split_whitespace() -> Result<(), String> {
        let splittable_data = "LOL  \n\tMANY\nROWS\n\n";

        let rows = split_whitespace(&splittable_data);

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2], "ROWS");

        Ok(())
    }

    #[test]
    fn test_get_bit() -> Result<(), String> {
        assert_eq!(get_bit!(0,0), 0);
        assert_eq!(get_bit!(1,0), 1);
        assert_eq!(get_bit!(2,0), 0);
        assert_eq!(get_bit!(3,0), 1);
        assert_eq!(get_bit!(4,0), 0);
        assert_eq!(get_bit!(4,1), 0);
        assert_eq!(get_bit!(4,2), 1);

        Ok(())
    }
}
