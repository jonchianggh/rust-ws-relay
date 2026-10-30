//! Adapt a WebSocket (message-framed) into a byte stream implementing
//! AsyncRead + AsyncWrite, so the protocol parsers can treat it like a socket.

use bytes::{Buf, BytesMut};
use futures_util::{Sink, Stream};
use hyper_tungstenite::tungstenite::Message;
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    /// Wraps any WebSocket that is a Stream + Sink of tungstenite Messages.
    pub struct WsByteStream<S> {
        #[pin]
        inner: S,
        read_buf: BytesMut,
        write_closed: bool,
    }
}

impl<S> WsByteStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
            write_closed: false,
        }
    }
}

impl<S, E> AsyncRead for WsByteStream<S>
where
    S: Stream<Item = Result<Message, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        loop {
            if !this.read_buf.is_empty() {
                let n = std::cmp::min(this.read_buf.len(), buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        this.read_buf.extend_from_slice(&data);
                    }
                    Message::Text(t) => this.read_buf.extend_from_slice(t.as_bytes()),
                    Message::Close(_) => return Poll::Ready(Ok(())), // EOF
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                },
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S, E> AsyncWrite for WsByteStream<S>
where
    S: Sink<Message, Error = E>,
    E: std::error::Error + Send + Sync + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let n = buf.len();
                match this
                    .inner
                    .as_mut()
                    .start_send(Message::Binary(buf.to_vec()))
                {
                    Ok(()) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        this.inner.poll_flush(cx).map_err(|e| io::Error::other(e))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if !*this.write_closed {
            match this.inner.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let _ = this.inner.as_mut().start_send(Message::Close(None));
                    *this.write_closed = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.inner.poll_close(cx).map_err(|e| io::Error::other(e))
    }
}
