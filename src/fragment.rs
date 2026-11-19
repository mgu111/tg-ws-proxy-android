use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{sleep, Sleep};

/// Обёртка над TcpStream, которая разрезает первый TLS-пакет (ClientHello)
/// на две части ровно посередине домена SNI с микропаузой 2 мс.
/// После отправки ClientHello переходит в 100% прозрачный режим.
pub struct FragmentedStream {
    inner: TcpStream,
    sni: Vec<u8>,
    handshake_done: bool,
    pending_chunks: Vec<Vec<u8>>,
    chunk_idx: usize,
    chunk_offset: usize,
    delay: Option<Pin<Box<Sleep>>>,
}

impl FragmentedStream {
    pub fn new(stream: TcpStream, sni_domain: &str) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            inner: stream,
            sni: sni_domain.as_bytes().to_vec(),
            handshake_done: false,
            pending_chunks: Vec::new(),
            chunk_idx: 0,
            chunk_offset: 0,
            delay: None,
        }
    }

    fn split_client_hello(&mut self, buf: &[u8]) {
        // TLS Handshake record начинается с 0x16
        if buf.len() > 10 && buf[0] == 0x16 && !self.sni.is_empty() {
            if let Some(pos) = buf.windows(self.sni.len()).position(|w| w == self.sni.as_slice()) {
                let mid_sni = pos + (self.sni.len() / 2);
                self.pending_chunks.push(buf[..mid_sni].to_vec());
                self.pending_chunks.push(buf[mid_sni..].to_vec());
                return;
            }
        }

        // Если SNI не найден (например, IP-адрес), режем заголовок TLS Record (первые 3 байта)
        if buf.len() > 5 {
            self.pending_chunks.push(buf[..3].to_vec());
            self.pending_chunks.push(buf[3..].to_vec());
        } else {
            self.pending_chunks.push(buf.to_vec());
        }
    }
}

impl AsyncRead for FragmentedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragmentedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        if this.handshake_done {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        if this.pending_chunks.is_empty() {
            this.split_client_hello(buf);
        }

        while this.chunk_idx < this.pending_chunks.len() {
            if let Some(delay) = &mut this.delay {
                if delay.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.delay = None;
            }

            let current_chunk = &this.pending_chunks[this.chunk_idx];
            let slice_to_write = &current_chunk[this.chunk_offset..];

            match Pin::new(&mut this.inner).poll_write(cx, slice_to_write) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write fragment",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.chunk_offset += n;
                    if this.chunk_offset >= current_chunk.len() {
                        this.chunk_idx += 1;
                        this.chunk_offset = 0;
                        if this.chunk_idx < this.pending_chunks.len() {
                            this.delay = Some(Box::pin(sleep(Duration::from_millis(2))));
                        }
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.handshake_done = true;
        this.pending_chunks.clear();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
