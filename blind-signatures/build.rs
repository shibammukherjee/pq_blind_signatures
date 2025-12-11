fn main() {
    // Specify the library search paths
    println!("cargo:rustc-link-search=../mayo-c-sys/target/debug");
    println!("cargo:rustc-link-search=../vole-mayo-sys/target/debug");

    // Specify the libraries to link
    println!("cargo:rustc-link-lib=mayo");
    println!("cargo:rustc-link-lib=volemayo");

    // Set the LD_LIBRARY_PATH environment variable for the build process
    println!(
        "cargo:rustc-env=DYLD_LIBRARY_PATH=../mayo-c-sys/target/debug:../vole-mayo-sys/target/debug"
    );

    // Set the DYLD_LIBRARY_PATH to make the linking work on macOS
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH=../mayo-c-sys/target/debug:../vole-mayo-sys/target/debug"
    );
}
