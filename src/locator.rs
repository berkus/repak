use {crate::io::leb128_usize, culpa::throws};

#[throws(std::io::Error)]
pub fn make_index_locator(offset: u64) -> Vec<u8> {
    let n = 64 - u64::from(offset.leading_zeros());
    // dbg!("Non-zero bits {}", n);
    // let align_down = fn(x: u64) -> u64 { x & !0x7f };
    let bsize = (n & !7) / 7;
    let off = offset + bsize + 1;
    // dbg!("Offset {} + {} + {} = {off} ({off:x})", offset, bsize, 1,);
    let lenbuf = leb128_usize(off)? as u64;
    // dbg!("Lenbuf {}", lenbuf);
    let mut buf = vec![];
    leb128::write::unsigned(&mut buf, offset + lenbuf).unwrap();
    buf.reverse();
    buf
}

#[cfg(test)]
mod index_locator_tests {
    use {super::make_index_locator, std::io::Cursor};

    fn prep(offset: u64) -> (Vec<u8>, u64) {
        let mut buf = make_index_locator(offset).expect("Shouldn't fail");
        buf.reverse();
        let check = leb128::read::unsigned(&mut Cursor::new(&buf)).unwrap();
        buf.reverse();
        (buf, check)
    }

    // 126 - 1b
    // 126+1 - 1b
    // So the end offset is 127 (126 index size + 1 locator size)
    #[test]
    fn locator_close_to_1byte() {
        let (buf, check) = prep(126);
        assert_eq!(buf, vec![0x7f]);
        assert_eq!(check, 127);
    }

    // 127 - 1b
    // 127+1 - 2b
    // 127+2 - 2b
    // So the end offset is 129 (127 index size + 2 locator size)
    #[test]
    fn locator_edgecase_1byte() {
        let (buf, check) = prep(127);
        assert_eq!(buf, vec![0x01, 0x81]);
        assert_eq!(check, 129);
    }

    // @todo: This fails, but should not - 16383 should fit into 2 bytes serialization
    #[test]
    fn locator_close_to_2bytes() {
        let (buf, check) = prep(16381);
        assert_eq!(buf, vec![0x7f, 0xff]);
        assert_eq!(check, 16383);
    }

    // 2-octet VLQ (0xFF7F) is 0b_11_1111_1111_1111 = 0x3FFE = 16382
    // 16382 - 2b
    // 16382+2 - 3b
    // 16382+3 - 3b
    // So the end offset is 16385 (16382 index size + 3 locator size)
    #[test]
    fn locator_edgecase_2bytes() {
        let (buf, check) = prep(16382);
        assert_eq!(buf, vec![0x01, 0x80, 0x81]);
        assert_eq!(check, 16385);
    }

    // 3-octet VLQ (0xFF_FF_7F) is 0b_1_1111_1111_1111_1111_1111 = 0x1FFFFF = 2097151
    // 2097151 - 3b
    // 2097151+3 - 4b
    // 2097151+4 - 4b
    // So the end offset is 2097155 (2097151 index size + 4 locator size)
    #[test]
    fn locator_edgecase_3bytes() {
        let (buf, check) = prep(2097151);
        assert_eq!(buf, vec![0x01, 0x80, 0x80, 0x83]);
        assert_eq!(check, 2097155);
    }

    #[test]
    fn locator_close_to_10bytes() {
        let (buf, check) = prep(u64::MAX / 4);
        assert_eq!(
            buf,
            vec![0x40, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x88]
        );
        assert_eq!(check, u64::MAX / 4 + 9);
    }

    #[test]
    fn locator_edgecase_10bytes() {
        let (buf, check) = prep(u64::MAX / 10 * 9);
        assert_eq!(
            buf,
            vec![0x01, 0xe6, 0xb3, 0x99, 0xcc, 0xe6, 0xb3, 0x99, 0xcc, 0xeb]
        );
        assert_eq!(check, u64::MAX / 10 * 9 + 10);
    }
}
