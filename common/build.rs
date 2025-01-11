use std::fs;
use std::path::Path;

fn main() {
    let src = Path::new("config.yaml");
    let dst_dir = Path::new("../");
    let dst = dst_dir.join("config.yaml");

    // 确保目标目录存在
    if !dst_dir.exists() {
        fs::create_dir_all(&dst_dir).expect("Failed to create target directory");
    }

    // 复制文件
    fs::copy(&src, &dst).expect("Failed to copy file");

    println!("cargo:rerun-if-changed=config.yaml");
}
