use libc::getpid;

#[link(name = "mylib")]
extern "C" {
    fn my_c_function(x: i32) -> i32;
}

fn call_ffi() {
    let _pid = unsafe { getpid() };
}
