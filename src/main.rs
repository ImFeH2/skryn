use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::Duration;

use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPARAM, LPVOID, TRUE, UINT};
use winapi::shared::windef::{HWND, RECT};
use winapi::um::dwmapi::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use winapi::um::wingdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteObject, GetDIBits, SelectObject,
    BITMAPFILEHEADER, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
};
use winapi::um::winuser::{
    BringWindowToTop, EnumWindows, GetDC, GetWindowLongW,
    GetWindowRect, GetWindowThreadProcessId, PrintWindow, ReleaseDC, SetForegroundWindow,
    SetWindowPos, GWL_EXSTYLE, HWND_TOPMOST, PW_RENDERFULLCONTENT, SWP_NOMOVE, SWP_NOSIZE
    , WS_EX_TOOLWINDOW,
};

#[derive(Debug)]
struct WindowSearchData {
    process_id: DWORD,
    window_handle: HWND,
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let search_data = &mut *(lparam as *mut WindowSearchData);
    let mut process_id: DWORD = 0;

    let style = GetWindowLongW(hwnd, GWL_EXSTYLE);
    if (style & WS_EX_TOOLWINDOW as i32) != 0 {
        return 1;
    }

    GetWindowThreadProcessId(hwnd, &mut process_id);

    if process_id == search_data.process_id {
        search_data.window_handle = hwnd;
        return FALSE;
    }

    TRUE
}

fn get_child_processes(parent_pid: DWORD) -> Vec<DWORD> {
    let mut child_pids = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return child_pids;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            while Process32NextW(snapshot, &mut entry) != 0 {
                if entry.th32ParentProcessID == parent_pid {
                    child_pids.push(entry.th32ProcessID);
                }
            }
        }

        CloseHandle(snapshot);
    }

    child_pids
}

fn find_window_for_process(process_ids: &[DWORD]) -> HWND {
    println!("Finding window for process IDs: {:?}", process_ids);

    unsafe {
        for &pid in process_ids {
            let mut search_data = WindowSearchData {
                process_id: pid,
                window_handle: null_mut(),
            };

            EnumWindows(
                Some(enum_windows_callback),
                &mut search_data as *mut WindowSearchData as LPARAM,
            );

            if !search_data.window_handle.is_null() {
                return search_data.window_handle;
            }
        }
    }

    null_mut()
}

fn create_process(program_path: &str) -> Option<PROCESS_INFORMATION> {
    let program_path_w: Vec<u16> = OsString::from(program_path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CreateProcessW(
            null(),
            program_path_w.as_ptr() as *mut u16,
            null_mut(),
            null_mut(),
            0,
            0,
            null_mut(),
            null_mut(),
            &mut startup_info,
            &mut process_info,
        )
    };

    if result == 0 {
        eprintln!("Failed to create process");
        None
    } else {
        Some(process_info)
    }
}

fn get_base_filename(path: &str) -> String {
    let path = Path::new(path);
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| "screenshot".to_string())
}

fn get_window_bounds(hwnd: HWND) -> RECT {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };

    unsafe {
        let result = DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut rect as *mut RECT as LPVOID,
            std::mem::size_of::<RECT>() as DWORD,
        );

        if result != 0 {
            GetWindowRect(hwnd, &mut rect);
        }
    }

    rect
}

fn save_bitmap_to_file(
    pixel_data: &[u8],
    width: i32,
    height: i32,
    stride: i32,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(format!("{}.bmp", filename))?;

    let file_header_size = std::mem::size_of::<BITMAPFILEHEADER>();
    let info_header_size = std::mem::size_of::<BITMAPINFOHEADER>();
    let pixel_data_size = (stride * height) as usize;

    let mut file_header = BITMAPFILEHEADER {
        bfType: 0x4D42,
        bfSize: (file_header_size + info_header_size + pixel_data_size) as DWORD,
        bfReserved1: 0,
        bfReserved2: 0,
        bfOffBits: (file_header_size + info_header_size) as DWORD,
    };

    let info_header = BITMAPINFOHEADER {
        biSize: info_header_size as DWORD,
        biWidth: width,
        biHeight: -height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB as DWORD,
        biSizeImage: pixel_data_size as DWORD,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };

    let bf_type_bytes: [u8; 2] = [(file_header.bfType & 0xFF) as u8, ((file_header.bfType >> 8) & 0xFF) as u8];
    file.write_all(&bf_type_bytes)?;
    file.write_all(&file_header.bfSize.to_le_bytes())?;
    file.write_all(&file_header.bfReserved1.to_le_bytes())?;
    file.write_all(&file_header.bfReserved2.to_le_bytes())?;
    file.write_all(&file_header.bfOffBits.to_le_bytes())?;

    let info_header_bytes = unsafe {
        std::slice::from_raw_parts(
            &info_header as *const BITMAPINFOHEADER as *const u8,
            info_header_size,
        )
    };
    file.write_all(info_header_bytes)?;
    file.write_all(pixel_data)?;

    println!("Screenshot saved to {}.bmp", filename);
    Ok(())
}

fn prepare_window_for_capture(hwnd: HWND) {
    unsafe {
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        thread::sleep(Duration::from_millis(500));
    }
}

fn capture_window_screenshot(hwnd: HWND, output_filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    prepare_window_for_capture(hwnd);

    let rect = get_window_bounds(hwnd);
    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    println!("Window size: {}x{}", width, height);

    let hdc_window = unsafe { GetDC(hwnd) };
    if hdc_window.is_null() {
        return Err("Failed to get device context for window".into());
    }

    let hdc_mem = unsafe { CreateCompatibleDC(hdc_window) };
    if hdc_mem.is_null() {
        unsafe { ReleaseDC(hwnd, hdc_window) };
        return Err("Failed to create compatible DC".into());
    }

    let hbitmap = unsafe { CreateCompatibleBitmap(hdc_window, width, height) };
    if hbitmap.is_null() {
        unsafe {
            ReleaseDC(hwnd, hdc_window);
            DeleteObject(hdc_mem as *mut _);
        };
        return Err("Failed to create compatible bitmap".into());
    }

    let old_bitmap = unsafe { SelectObject(hdc_mem, hbitmap as *mut _) };

    let result = unsafe {
        PrintWindow(hwnd, hdc_mem, PW_RENDERFULLCONTENT)
    };

    if result == 0 {
        println!("PrintWindow failed, falling back to BitBlt");
        let bitblt_result = unsafe {
            BitBlt(hdc_mem, 0, 0, width, height, hdc_window, 0, 0, SRCCOPY)
        };

        if bitblt_result == 0 {
            unsafe {
                SelectObject(hdc_mem, old_bitmap);
                DeleteObject(hbitmap as *mut _);
                DeleteObject(hdc_mem as *mut _);
                ReleaseDC(hwnd, hdc_window);
            };
            return Err("Failed to copy window contents to bitmap".into());
        }
    }

    let bytes_per_pixel = 4;
    let stride = ((width * bytes_per_pixel + 3) / 4) * 4;
    let mut pixel_data: Vec<u8> = vec![0; (stride * height) as usize];

    let mut bmi = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as DWORD,
        biWidth: width,
        biHeight: -height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB as DWORD,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };

    let scan_lines = unsafe {
        GetDIBits(
            hdc_mem,
            hbitmap,
            0,
            height as UINT,
            pixel_data.as_mut_ptr() as LPVOID,
            &mut bmi as *mut _ as *mut _,
            DIB_RGB_COLORS,
        )
    };

    unsafe {
        SelectObject(hdc_mem, old_bitmap);
        DeleteObject(hbitmap as *mut _);
        DeleteObject(hdc_mem as *mut _);
        ReleaseDC(hwnd, hdc_window);
    };

    if scan_lines == 0 || scan_lines != height as i32 {
        return Err("Failed to get bitmap data".into());
    }

    println!("Screenshot captured successfully.");
    render_ascii_art(&pixel_data, width, height, stride, bytes_per_pixel);
    save_bitmap_to_file(&pixel_data, width, height, stride, output_filename)?;
    Ok(())
}

fn render_ascii_art(pixel_data: &[u8], width: i32, height: i32, stride: i32, bytes_per_pixel: i32) {
    let sample_step = std::cmp::max(1, std::cmp::min(width, height) / 80);

    for y in (0..height).step_by(sample_step as usize * 2) {
        for x in (0..width).step_by(sample_step as usize) {
            let offset = (y * stride + x * bytes_per_pixel) as usize;
            if offset + 2 < pixel_data.len() {
                let b = pixel_data[offset];
                let g = pixel_data[offset + 1];
                let r = pixel_data[offset + 2];
                let brightness = (r as u16 + g as u16 + b as u16) / 3;

                let ch = match brightness {
                    0..=25 => ' ',
                    26..=50 => '.',
                    51..=75 => ':',
                    76..=100 => '-',
                    101..=125 => '=',
                    126..=150 => '+',
                    151..=175 => '*',
                    176..=200 => '#',
                    201..=225 => '%',
                    _ => '@',
                };

                print!("{}", ch);
            }
        }
        println!();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: skyrn <program_path>");
        return Ok(());
    }

    let program_path = &args[1];
    println!("Launching process: {}", program_path);

    let filename = get_base_filename(program_path);

    let process_info = match create_process(program_path) {
        Some(info) => info,
        None => return Ok(()),
    };

    println!("Process created. Waiting for window to initialize...");
    thread::sleep(Duration::from_secs(5));

    println!(
        "Looking for window with process ID: {}",
        process_info.dwProcessId
    );

    let mut process_ids = vec![process_info.dwProcessId];
    process_ids.extend(get_child_processes(process_info.dwProcessId));

    let hwnd = find_window_for_process(&process_ids);
    if hwnd.is_null() {
        eprintln!("Could not find window for process or its children");
        unsafe {
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
        }
        return Ok(());
    }
    println!("Window found. Capturing screenshot...");

    if let Err(e) = capture_window_screenshot(hwnd, &filename) {
        eprintln!("Screenshot error: {}", e);
    }

    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }

    Ok(())
}
