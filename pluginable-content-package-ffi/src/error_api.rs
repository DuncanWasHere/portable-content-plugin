use super::*;

#[unsafe(no_mangle)]
/// Copies the calling thread's last detailed ABI error as a C string and returns the required byte count.
///
/// # Safety
/// A non-null `destination` must reference `destination_byte_count` writable bytes.
pub unsafe extern "C" fn pcp_last_error_message(
    destination: *mut c_char,
    destination_byte_count: usize,
) -> usize {
    LAST_ERROR.with(|slot| {
        let message = slot.borrow();
        let required = message.len() + 1;
        if !destination.is_null() && destination_byte_count > 0 {
            let copied = message.len().min(destination_byte_count - 1);
            // SAFETY: Caller provides destination_byte_count writable bytes.
            unsafe {
                ptr::copy_nonoverlapping(message.as_ptr(), destination.cast::<u8>(), copied);
                destination.add(copied).write(0);
            }
        }
        required
    })
}
