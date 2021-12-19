pub fn int_to_string_binary(input: i32) -> String
{
  let mut output: [i32; 32] = [0; 32];
  let mut num: i32 = input;
  let mut i = 0;
  while num > 0
  {
    output[31-i] = num % 2;
    num = num / 2;
    i += 1;
  }
  let mut string_output = String::new();
  for x in output.iter()
  {
    string_output = string_output + &x.to_string();
  }
  string_output
}

pub fn convert_binary_to_int(input: &str) -> u32
{
  let mut num = 0;
  let input_array: Vec<char>  = input.chars().collect();
  let input_len = input.len();
  for x in 0..input_len
  {
    if input_array[input_len - x - 1] == '1'
    {
      num += u32::pow(2, x as u32);
    }
  }
  num
}

pub fn sha256_digest(data: &str) -> std::vec::Vec::<u32>
{
  let mut h0: u32 = 0x6a09e667;
  let mut h1: u32 = 0xbb67ae85;
  let mut h2: u32 = 0x3c6ef372;
  let mut h3: u32 = 0xa54ff53a;
  let mut h4: u32 = 0x510e527f;
  let mut h5: u32 = 0x9b05688c;
  let mut h6: u32 = 0x1f83d9ab;
  let mut h7: u32 = 0x5be0cd19;

  let k: [u32; 64] =
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
     0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
     0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
     0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
     0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
     0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

  let data_length = data.len() * 8; //in bits
  let data_as_bytes = data.as_bytes();

  let additional_padding_length = 512 - ((data_length + 1 + 64) % 512);
  let overall_length = (data_length + 1 + additional_padding_length + 64) / 32;
  let mut new_vec = vec![0 as u32; overall_length];
  for x in 0..data.len()
  {
    new_vec[(x / 4)] += (data_as_bytes[x] as u32) << (24 - (x % 4)*8);
  }
  new_vec[(data.len() / 4)] += (128 as u32) << (24 - (data.len() % 4)*8);
  let data_len = (data.len() * 8) as u64;
  
  new_vec[overall_length - 2] = (data_len >> 32) as u32;
  new_vec[overall_length - 1] = data_len as u32;

  let num_chunks = new_vec.len() * 32 / 512 ;
  for x in 0..num_chunks
  {
    let mut message_schedule =  vec![0 as u32; 64];
    for i in 0..16
    {
      message_schedule[i] = new_vec[x*16+i];
    }
    for i in 16..64
    {
      let s0 = (message_schedule[i-15].rotate_right(7)) ^ ( message_schedule[i-15].rotate_right(18)) ^ (message_schedule[i-15] >> 3);
      let s1 = (message_schedule[i-2].rotate_right(17)) ^ (message_schedule[i-2].rotate_right(19)) ^ (message_schedule[i-2] >> 10);
      message_schedule[i] = message_schedule[i-16].wrapping_add(s0).wrapping_add(message_schedule[i-7]).wrapping_add(s1);      
    }

    let mut a: u32 = h0;
    let mut b: u32 = h1;
    let mut c: u32 = h2;
    let mut d: u32 = h3;
    let mut e: u32 = h4;
    let mut f: u32 = h5;
    let mut g: u32 = h6;
    let mut h: u32 = h7;

    for i in 0..64
    {
      let s_1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
      let ch = (e & f) ^ ((!e) & g);
      let temp1 = h.wrapping_add(s_1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(message_schedule[i]);
      let s_0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
      let maj = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = s_0.wrapping_add(maj);      
    
      h = g;
      g = f;
      f = e;
      e = d.wrapping_add(temp1);
      d = c;
      c = b;
      b = a;
      a = temp1.wrapping_add(temp2);
    }

    h0 = h0.wrapping_add(a);
    h1 = h1.wrapping_add(b);
    h2 = h2.wrapping_add(c);
    h3 = h3.wrapping_add(d);
    h4 = h4.wrapping_add(e);
    h5 = h5.wrapping_add(f);
    h6 = h6.wrapping_add(g);
    h7 = h7.wrapping_add(h);
  }  
  let digest_u32 = vec![h0, h1, h2, h3, h4, h5, h6, h7];

  digest_u32
}

pub fn sha256(data: &str) -> String
{
  let digest_u32 = sha256_digest(data);
  let hash = vec![format!("{:08X}", digest_u32[0]),
                  format!("{:08X}", digest_u32[1]),
                  format!("{:08X}", digest_u32[2]),
                  format!("{:08X}", digest_u32[3]),
                  format!("{:08X}", digest_u32[4]),
                  format!("{:08X}", digest_u32[5]),
                  format!("{:08X}", digest_u32[6]),
                  format!("{:08X}", digest_u32[7])].join("");
  hash

}

pub fn sha256_bytes(data: &str) -> std::vec::Vec<u8>
{
  let digest_u32 = sha256_digest(data);
  let mut bytes = vec![0 as u8; 8*4];
  for i in 0..bytes.len()
  {
    bytes[i] = (digest_u32[i/4] >> (24 - (i % 4) * 8)) as u8;
  }
  bytes
}

#[cfg(test)]
mod tests
{
  use super::*;

  #[test]
  fn it_works()
  {
    assert_eq!(2 + 2, 4);
    //convert_int_to_binary(104);
    //convert_int_to_binary(101);
    //convert_int_to_binary(108);
    //convert_int_to_binary(108);
   
    //convert_binary_to_int("00000000000000000000000001101000");
    //convert_binary_to_int("00000000000000000000000001100101");
    //convert_binary_to_int("00000000000000000000000001101100");
    //convert_binary_to_int("00000000000000000000000001101100");
    //convert_binary_to_int("01101000011001010110110001101100"); 
  }

  #[test]
  fn sha256_tests()
  {
    assert_eq!(sha256(""), "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
    assert_eq!(sha256("a"), "CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB");
    assert_eq!(sha256("abc"), "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    assert_eq!(sha256("message digest"), "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650");
    assert_eq!(sha256("abcdefghijklmnopqrstuvwxyz"), "71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73");
    assert_eq!(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
    assert_eq!(sha256("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0");
    assert_eq!(sha256("1234567890".repeat(8).as_str()), "F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E");
    assert_eq!(sha256("a".repeat(1_000_000).as_str()), "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0");
  }
}
