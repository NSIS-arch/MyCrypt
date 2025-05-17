use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce}; // AES-GCM-SIV için daha güvenli streaming
use aes_gcm_siv::aead::{Aead, KeyInit, OsRng};
use clap::{Parser, Subcommand};
use rand::RngCore;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter, Seek, SeekFrom};
use std::path::PathBuf;
use rpassword::prompt_password;
use thiserror::Error;
use argon2::Argon2;
use zeroize::{Zeroize, Zeroizing};
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use std::time::Duration;
use std::collections::HashMap;

const MAGIC_BYTES: &[u8] = b"MYCRYPT2";
const VERSION: u8 = 1;
const NONCE_SIZE: usize = 12;
const HMAC_SIZE: usize = 32;
const SALT_SIZE: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB'lık chunk'lar

// Özel hata türleri
#[derive(Error, Debug)]
enum MyCryptError {
    #[error("Dosya I/O hatası: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Şifreleme hatası: {0}")]
    EncryptionError(String),
    
    #[error("Şifre çözme hatası: {0}")]
    DecryptionError(String),
    
    #[error("Doğrulama hatası: {0}")]
    ValidationError(String),
    
    #[error("Geçersiz dosya formatı: {0}")]
    InvalidFormat(String),
    
    #[error("Kullanıcı hatası: {0}")]
    UserError(String),
    
    #[error("Genel hata: {0}")]
    GeneralError(String),
}

type Result<T> = std::result::Result<T, MyCryptError>;

#[derive(Parser)]
#[clap(name = "MyCrypt", version, author, about = "Gelişmiş AES-GCM-SIV tabanlı dosya şifreleme ve çözme aracı")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(
            short, 
            long, 
            required = true,
            help = "Şifrelenecek dosya veya dosyalar (birden fazla dosya boşlukla ayrılabilir)",
            value_name = "DOSYA",
            num_args = 1..,
            value_parser
        )]
        input: Vec<PathBuf>,

        #[arg(short, long, help = "Çıktı dosyası (yalnızca 1 dosya için geçerli)")]
        output: Option<PathBuf>,
        
        #[arg(short, long, help = "Chunk boyutu (KB, varsayılan: 1024KB/1MB)")]
        chunk_size: Option<usize>,
    },
    Decrypt {
        #[arg(
            short, 
            long, 
            required = true,
            help = "Çözülecek dosya veya dosyalar (birden fazla dosya boşlukla ayrılabilir)",
            value_name = "DOSYA",
            num_args = 1..,
            value_parser
        )]
        input: Vec<PathBuf>,

        #[arg(short, long, help = "Çıktı dosyası (yalnızca 1 dosya için geçerli)")]
        output: Option<PathBuf>,
        
        #[arg(short, long, help = "Chunk boyutu (KB, varsayılan: 1024KB/1MB)")]
        chunk_size: Option<usize>,
    },
}

// Şifreli dosyanın başlık bilgilerini tutan yapı
#[derive(Debug)]
struct FileHeader {
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    hmac: [u8; HMAC_SIZE],
}

impl FileHeader {
    fn new() -> Self {
        Self {
            salt: [0u8; SALT_SIZE],
            nonce: [0u8; NONCE_SIZE],
            hmac: [0u8; HMAC_SIZE],
        }
    }
    
    fn generate(&mut self) {
        OsRng.fill_bytes(&mut self.salt);
        OsRng.fill_bytes(&mut self.nonce);
        // hmac daha sonra hesaplanacak
    }
    
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.salt)
            .map_err(MyCryptError::from)?;
        writer.write_all(&self.nonce)
            .map_err(MyCryptError::from)?;
        writer.write_all(&self.hmac)
            .map_err(MyCryptError::from)?;
        Ok(())
    }
    
    fn read_from<R: Read>(&mut self, reader: &mut R) -> Result<()> {
        reader.read_exact(&mut self.salt)
            .map_err(MyCryptError::from)?;
        reader.read_exact(&mut self.nonce)
            .map_err(MyCryptError::from)?;
        reader.read_exact(&mut self.hmac)
            .map_err(MyCryptError::from)?;
        Ok(())
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt, &mut *key)
        .expect("Anahtar türetme hatası");
    key
}

fn get_password(prompt: &str) -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(prompt_password(prompt)
        .map_err(|e| MyCryptError::UserError(format!("Şifre okunamadı: {}", e)))?);
    
    if password.is_empty() {
        return Err(MyCryptError::UserError("Şifre boş olamaz".to_string()));
    }
    Ok(password)
}

fn verify_password_for_encrypt() -> Result<Zeroizing<String>> {
    let password = get_password("Şifre: ")?;
    let password_verify = get_password("Şifreyi tekrar girin: ")?;
    
    if *password != *password_verify {
        return Err(MyCryptError::UserError("Şifreler uyuşmuyor".to_string()));
    }
    
    Ok(password)
}

fn get_password_for_decrypt() -> Result<Zeroizing<String>> {
    get_password("Şifre: ")
}

fn calculate_hmac(key: &[u8], data: &[u8], header: &FileHeader) -> Zeroizing<[u8; HMAC_SIZE]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC anahtar oluşturulamadı");
    
    // Bütünlük kontrolünü salt ve nonce dahil yapacağız
    mac.update(&header.salt);
    mac.update(&header.nonce);
    mac.update(data);
    
    let mut hmac_result = Zeroizing::new([0u8; HMAC_SIZE]);
    hmac_result.copy_from_slice(&mac.finalize().into_bytes()[..HMAC_SIZE]);
    hmac_result
}

fn verify_hmac(key: &[u8], data: &[u8], header: &FileHeader) -> Result<()> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC anahtar oluşturulamadı");
    
    // Doğrulama işlemi salt ve nonce dahil
    mac.update(&header.salt);
    mac.update(&header.nonce);
    mac.update(data);
    
    mac.verify_slice(&header.hmac)
        .map_err(|_| MyCryptError::ValidationError("Dosya bütünlüğü doğrulanamadı veya yanlış şifre".to_string()))
}

fn encrypt_file(input: &PathBuf, output: Option<&PathBuf>, password: &str, chunk_size: usize) -> Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .map_err(|e| MyCryptError::GeneralError(format!("ProgressBar hatası: {}", e)))?
    );
    pb.set_message(format!("'{}' dosyası hazırlanıyor...", input.display()));
    // Girdi dosyası açılır
    let input_file = File::open(input)
        .map_err(|e| MyCryptError::IoError(e))?;
    let input_metadata = input_file.metadata()
        .map_err(|e| MyCryptError::IoError(e))?;
    let total_size = input_metadata.len();
    let reader = BufReader::new(input_file);
    
    // Çıktı dosyası hazırlanır
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| input.with_extension("mycrypt"));
    let out_file = File::create(&out_path)
        .map_err(|e| MyCryptError::IoError(e))?;
    let mut writer = BufWriter::new(out_file);
    
    // Header hazırlanır
    pb.set_message(format!("'{}' için rastgele değerler üretiliyor...", input.display()));
    let mut header = FileHeader::new();
    header.generate();
    
    // Anahtar türetilir
    let key = derive_key(password, &header.salt);
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&*key));
    
    // Dosya başlık bilgileri yazılır
    writer.write_all(MAGIC_BYTES)
        .map_err(MyCryptError::from)?;
    writer.write_all(&[VERSION])
        .map_err(MyCryptError::from)?;
    
    // İlerleme çubuğu güncellenir
    pb.set_message(format!("'{}' şifreleniyor...", input.display()));
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} şifrelendi ({eta}) {msg}")
            .map_err(|e| MyCryptError::GeneralError(format!("ProgressBar hatası: {}", e)))?
            .progress_chars("#>-")
    );
    pb.set_length(total_size);
    
    // Şifrelenmiş verinin yazılacağı bellek temelli dizi
    let mut all_ciphertext = Vec::new();
    
    // Header yazılır
    header.write_to(&mut writer)?;
    
    // Chunk tabanlı işleme
    let mut buffer = vec![0u8; chunk_size];
    let mut bytes_read_total = 0u64;
    let mut reader = reader; // Mutable binding for our reader
    
    loop {
        // Doğrudan buffer'a okuma yapıyoruz
        let bytes_read = reader.read(&mut buffer)
            .map_err(MyCryptError::from)?;
        
        if bytes_read == 0 {
            break;
        }
        
        bytes_read_total += bytes_read as u64;
        pb.set_position(bytes_read_total);
        
        // Okunan veriyi şifreleme
        let encrypted_chunk = cipher
            .encrypt(Nonce::from_slice(&header.nonce), &buffer[0..bytes_read])
            .map_err(|e| MyCryptError::EncryptionError(format!("Şifreleme başarısız: {:?}", e)))?;
        
        // Şifrelenmiş veriye eklenir
        all_ciphertext.extend_from_slice(&encrypted_chunk);
    }
    
    // HMAC hesaplanır - bütün şifreli veri üzerinde
    pb.set_message(format!("'{}' için bütünlük kontrolü hesaplanıyor...", input.display()));
    let hmac = calculate_hmac(&key[..], &all_ciphertext, &header);
    header.hmac.copy_from_slice(&hmac[..]);
    
    // HMAC başlık bilgisi güncellenir - seek back ve güncelleme
    let hmac_offset = MAGIC_BYTES.len() + 1 + SALT_SIZE + NONCE_SIZE;
    writer.flush().map_err(MyCryptError::from)?;
    let mut file = writer.into_inner().map_err(|e| MyCryptError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    file.seek(SeekFrom::Start(hmac_offset as u64)).map_err(MyCryptError::from)?;
    file.write_all(&header.hmac).map_err(MyCryptError::from)?;
    
    // Şifreli veri yazılır
    file.seek(SeekFrom::End(0)).map_err(MyCryptError::from)?;
    file.write_all(&all_ciphertext).map_err(MyCryptError::from)?;
    file.flush().map_err(MyCryptError::from)?;
    
    // Belleğin temizlenmesi
    buffer.zeroize();
    all_ciphertext.zeroize();
    
    pb.finish_with_message(format!("✓ '{}' dosyası şifrelendi -> '{}'", input.display(), out_path.display()));
    Ok(())
}

fn decrypt_file(input: &PathBuf, output: Option<&PathBuf>, password: &str, _chunk_size: usize) -> Result<()> {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .map_err(|e| MyCryptError::GeneralError(format!("ProgressBar hatası: {}", e)))?
    );
    pb.set_message(format!("'{}' dosyası açılıyor...", input.display()));
    // Girdi dosyası açılır
    let mut file = File::open(input)
        .map_err(|e| MyCryptError::IoError(e))?;
    let file_size = file.metadata()
        .map_err(|e| MyCryptError::IoError(e))?.len();
    
    // Başlık kontrol edilir
    pb.set_message(format!("'{}' başlık bilgileri okunuyor...", input.display()));
    let mut magic = [0u8; MAGIC_BYTES.len()];
    file.read_exact(&mut magic)
        .map_err(MyCryptError::from)?;
    
    if magic != MAGIC_BYTES {
        return Err(MyCryptError::InvalidFormat(format!(
            "Geçersiz dosya formatı veya eski versiyon: {:?}. Beklenen imza: {:?}, bulunan: {:?}", 
            input, MAGIC_BYTES, magic)));
    }
    
    // Versiyon kontrolü
    let mut version = [0u8; 1];
    file.read_exact(&mut version)
        .map_err(MyCryptError::from)?;
    
    if version[0] != VERSION {
        return Err(MyCryptError::InvalidFormat(format!(
            "Desteklenmeyen dosya versiyonu: {}. Bu programın desteklediği versiyon: {}", 
            version[0], VERSION)));
    }
    
    // Header bilgileri okunur
    let mut header = FileHeader::new();
    header.read_from(&mut file)?;
    
    // Anahtar türetilir
    pb.set_message(format!("'{}' için anahtar türetiliyor...", input.display()));
    let key = derive_key(password, &header.salt);
    
    // Şifreli veri okunur
    pb.set_message(format!("'{}' şifreli veri okunuyor...", input.display()));
    let header_size = MAGIC_BYTES.len() + 1 + SALT_SIZE + NONCE_SIZE + HMAC_SIZE;
    let ciphertext_size = file_size as usize - header_size;
    let mut ciphertext = vec![0u8; ciphertext_size];
    file.read_exact(&mut ciphertext)
        .map_err(MyCryptError::from)?;
    
    // HMAC doğrulaması yapılır
    pb.set_message(format!("'{}' bütünlük kontrol ediliyor...", input.display()));
    verify_hmac(&key[..], &ciphertext, &header)?;
    
    // Deşifreleme için hazırlık
    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(&*key));
    
    // Çıktı dosyası açılır
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            let mut output_name = input.file_stem().unwrap_or_default().to_os_string();
            output_name.push(".decrypted");
            input.with_file_name(output_name)
        });
    
    if out_path.exists() {
        return Err(MyCryptError::UserError(format!("Hedef dosya zaten mevcut: {:?}", out_path)));
    }
    
    let output_file = File::create(&out_path)
        .map_err(|e| MyCryptError::IoError(e))?;
    let mut writer = BufWriter::new(output_file);
    
    // Şifre çözme işlemi
    pb.set_message(format!("'{}' şifresi çözülüyor...", input.display()));
    
    // Deşifreleme işlemi - geliştirilmiş hata mesajları ile
    let plaintext = match cipher.decrypt(Nonce::from_slice(&header.nonce), ciphertext.as_ref()) {
        Ok(pt) => pt,
        Err(e) => {
            return Err(MyCryptError::DecryptionError(format!(
                "Anahtar yanlış veya dosya bozuk: {}. Detay: {}", input.display(), e)));
        }
    };
    
    // Çözülen veri yazılır
    pb.set_message(format!("'{}' çözülmüş veri yazılıyor...", out_path.display()));
    writer.write_all(&plaintext)
        .map_err(MyCryptError::from)?;
    writer.flush()
        .map_err(MyCryptError::from)?;
    
    // Bellek temizliği
    ciphertext.zeroize();
    let mut plaintext_mut = plaintext;
    plaintext_mut.zeroize();
    
    pb.finish_with_message(format!("✓ '{}' dosyasının şifresi çözüldü -> '{}'", input.display(), out_path.display()));
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Varsayılan chunk boyutu (1MB)
    let default_chunk_size = CHUNK_SIZE;

    match cli.command {
        Commands::Encrypt { input, output, chunk_size } => {
            if output.is_some() && input.len() > 1 {
                return Err(Box::new(MyCryptError::UserError(
                    "-o/--output parametresi yalnızca tek dosya için kullanılabilir.".to_string()
                )));
            }
            
            // Şifre şifreleme için iki kez onaylanır
            let password = verify_password_for_encrypt()?;
            let chunk = chunk_size.unwrap_or(default_chunk_size / 1024) * 1024;
            
            let mp = MultiProgress::new();
            let main_pb = mp.add(ProgressBar::new(input.len() as u64));
            main_pb.set_style(
                ProgressStyle::with_template(
                    "{spinner} [{bar:40.cyan/blue}] {pos}/{len} dosya ({eta}) {msg}")
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(MyCryptError::GeneralError(e.to_string())) })?
            );
            
            for file in &input {
                main_pb.set_message(format!("{} işleniyor...", file.display()));
                
                let out = output.as_ref().filter(|_| input.len() == 1);
                if let Err(e) = encrypt_file(file, out, &password, chunk) {
                    main_pb.println(format!("✗ '{}' şifrelenirken hata: {}", file.display(), e));
                }
                
                main_pb.inc(1);
            }
            
            main_pb.finish_with_message("Tüm dosyalar şifrelendi");
        }
        Commands::Decrypt { input, output, chunk_size } => {
            if output.is_some() && input.len() > 1 {
                return Err(Box::new(MyCryptError::UserError(
                    "-o/--output parametresi yalnızca tek dosya için kullanılabilir.".to_string()
                )));
            }

            // Şifre çözme için sadece bir kez şifre alınır
            let password = get_password_for_decrypt()?;
            let chunk = chunk_size.unwrap_or(default_chunk_size / 1024) * 1024;
            
            let mp = MultiProgress::new();
            let main_pb = mp.add(ProgressBar::new(input.len() as u64));
            main_pb.set_style(
                ProgressStyle::with_template(
                    "{spinner} [{bar:40.cyan/blue}] {pos}/{len} dosya ({eta}) {msg}")
                .map_err(|e| -> Box<dyn std::error::Error> { Box::new(MyCryptError::GeneralError(e.to_string())) })?
            );

            // Salt değerlerine göre gruplandırma için
            let mut groups: HashMap<Vec<u8>, Vec<&PathBuf>> = HashMap::new();

            for file in &input {
                main_pb.set_message(format!("{} analiz ediliyor...", file.display()));
                
                if let Ok(mut f) = File::open(file) {
                    let mut header = [0u8; MAGIC_BYTES.len()];
                    let mut version = [0u8; 1];
                    if f.read_exact(&mut header).is_ok() && header == MAGIC_BYTES 
                       && f.read_exact(&mut version).is_ok() && version[0] == VERSION {
                        let mut salt = [0u8; SALT_SIZE];
                        if f.read_exact(&mut salt).is_ok() {
                            // Anahtarı değil sadece salt'ı saklıyoruz güvenlik için
                            let salt_vec = salt.to_vec();
                            groups.entry(salt_vec).or_default().push(file);
                        }
                    }
                }
                main_pb.inc(1);
            }

            main_pb.finish_with_message(format!("{} dosya analiz edildi, {} grup bulundu", input.len(), groups.len()));

            for (_, files) in groups {
                let group_pb = mp.add(ProgressBar::new(files.len() as u64));
                group_pb.set_style(
                    ProgressStyle::with_template(
                        "  {spinner} [{bar:30.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .map_err(|e| -> Box<dyn std::error::Error> { Box::new(MyCryptError::GeneralError(e.to_string())) })?
                );

                for file in files {
                    group_pb.set_message(format!("{} çözülüyor...", file.display()));
                    
                    let out_path = output.as_ref().filter(|_| input.len() == 1);
                    match decrypt_file(file, out_path, &password, chunk) {
                        Ok(_) => group_pb.println(format!("  ✓ {} başarıyla çözüldü", file.display())),
                        Err(e) => group_pb.println(format!("  ✗ {} çözülürken hata: {}", file.display(), e)),
                    }
                    
                    group_pb.inc(1);
                }
                
                group_pb.finish_with_message("Grup tamamlandı");
            }
        }
    }

    Ok(())
}