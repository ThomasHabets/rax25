/*
 *
 * man pcap-savefile
 *
 * For now use LINKTYPE_AX25, or number 3, with just AX.25.
 *
 * In the future maybe use LINKTYPE_AX25_KISS, 202.
 *
 * global header.
 *
     typedef struct pcap_hdr_s {
            guint32 magic_number;   /* magic number */
            guint16 version_major;  /* major version number */
            guint16 version_minor;  /* minor version number */
            gint32  thiszone;       /* GMT to local correction */
            guint32 sigfigs;        /* accuracy of timestamps */
            guint32 snaplen;        /* max length of captured packets, in octets */
            guint32 network;        /* data link type */
    } pcap_hdr_t;

 typedef struct pcaprec_hdr_s {
            guint32 ts_sec;         /* timestamp seconds */
            guint32 ts_usec;        /* timestamp microseconds */
            guint32 incl_len;       /* number of octets of packet saved in file */
            guint32 orig_len;       /* actual length of packet */
    } pcaprec_hdr_t;
*/

use std::io::BufWriter;
use std::io::Write;

use anyhow::Result;

const MAGIC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const LINKTYPE_AX25: u32 = 3;

fn write_u16(mut w: impl std::io::Write, v: u16) -> Result<()> {
    w.write_all(&[(v & 0xff) as u8, ((v >> 8) & 0xFF) as u8])?;
    Ok(())
}

fn write_u32(mut w: impl std::io::Write, v: u32) -> Result<()> {
    w.write_all(&[
        (v & 0xff) as u8,
        ((v >> 8) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
    ])?;
    Ok(())
}

pub struct PcapWriter {
    f: BufWriter<std::fs::File>,
}
impl PcapWriter {
    pub fn create(filename: std::path::PathBuf) -> Result<Self> {
        let mut f = BufWriter::new(
            std::fs::File::options()
                .read(false)
                .write(true)
                .create_new(true)
                .open(filename)?,
        );
        f.write_all(&MAGIC)?;
        write_u16(&mut f, VERSION_MAJOR)?;
        write_u16(&mut f, VERSION_MINOR)?;
        write_u32(&mut f, 0)?; // GMT offset. TODO: actually i32.
        write_u32(&mut f, 0)?; // figs?
        write_u32(&mut f, 1500)?; // TODO: snaplen
        write_u32(&mut f, LINKTYPE_AX25)?;
        Ok(Self { f })
    }

    pub fn write(&mut self, packet: &[u8]) -> Result<()> {
        let len = packet.len() as u32;
        let now = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)?;
        // TODO: Ugh, the pcap format is not Y2036 safe. What do we do here?
        write_u32(&mut self.f, now.as_secs() as u32)?;
        write_u32(&mut self.f, (now.as_micros() % 1000000) as u32)?;
        write_u32(&mut self.f, len)?;
        write_u32(&mut self.f, len)?;
        self.f.write_all(packet)?;
        Ok(())
    }
}
