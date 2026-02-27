// Copyright 2020 Mostyn Bramley-Moore.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package zstd is a wrapper for using github.com/klauspost/compress/zstd
// with gRPC.
package zstd

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"sync"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/grpc/encoding"
)

const Name = "zstd"

var encoderOptions = []zstd.EOption{
	// The default zstd window size is 8MB, which is much larger than the
	// typical RPC message and wastes a bunch of memory.
	zstd.WithWindowSize(512 * 1024),
	// Since we only use the stateless EncodeAll method, we don't need the
	// background goroutines that the encoder spawns for streaming. Without
	// this, the encoder spawns GOMAXPROCS goroutines that are never used.
	zstd.WithEncoderConcurrency(1),
}

var decoderOptions = []zstd.DOption{
	// If the decoder concurrency level is not 1, we would need to call
	// Close() to avoid leaking resources when the object is released
	// from compressor.decoderPool.
	zstd.WithDecoderConcurrency(1),
}

// decoderWrapper returns the decoder to the pool eagerly on EOF (the normal
// read completion path), rather than deferring to a GC finalizer. This avoids
// accumulating idle decoders and their history buffers between GC cycles.
// The finalizer is kept as a safety net for abandoned readers (e.g. error
// paths where gRPC discards the reader before reaching EOF).
//
// The decoder is stored as a named field (not embedded) to avoid promoting
// *zstd.Decoder.Close(), which would make decoderWrapper satisfy io.Closer.
// If a consumer called Close(), the decoder would be permanently unusable
// and could never be returned to the pool.
type decoderWrapper struct {
	decoder  *zstd.Decoder
	pool     *sync.Pool
	returned bool
}

func (dw *decoderWrapper) Read(p []byte) (int, error) {
	n, err := dw.decoder.Read(p)
	if err == io.EOF {
		dw.returnToPool()
	}
	return n, err
}

func (dw *decoderWrapper) returnToPool() {
	if dw.returned {
		return
	}
	dw.returned = true
	if err := dw.decoder.Reset(nil); err == nil {
		dw.pool.Put(dw.decoder)
	}
}

type compressor struct {
	encoder     *zstd.Encoder
	decoderPool sync.Pool // To hold *zstd.Decoder's.
}

func PretendInit(clobbering bool) {
	if !clobbering && encoding.GetCompressor(Name) != nil {
		return
	}

	enc, _ := zstd.NewWriter(nil, encoderOptions...)
	c := &compressor{
		encoder: enc,
	}
	encoding.RegisterCompressor(c)
}

var ErrNotInUse = errors.New("SetLevel ineffective because another zstd compressor has been registered")

// SetLevel updates the registered compressor to use a particular compression
// level. NOTE: this function must only be called from an init function, and
// is not threadsafe.
func SetLevel(level zstd.EncoderLevel) error {
	c, ok := encoding.GetCompressor(Name).(*compressor)
	if !ok {
		return ErrNotInUse
	}

	enc, err := zstd.NewWriter(nil, append(encoderOptions, zstd.WithEncoderLevel(level))...)
	if err != nil {
		return err
	}

	c.encoder.Close()
	c.encoder = enc
	return nil
}

func (c *compressor) Compress(w io.Writer) (io.WriteCloser, error) {
	return &zstdWriteCloser{
		enc:    c.encoder,
		writer: w,
	}, nil
}

type zstdWriteCloser struct {
	enc    *zstd.Encoder
	writer io.Writer    // Compressed data will be written here.
	buf    bytes.Buffer // Buffer uncompressed data here, compress on Close.
}

func (z *zstdWriteCloser) Write(p []byte) (int, error) {
	return z.buf.Write(p)
}

func (z *zstdWriteCloser) Close() error {
	compressed := z.enc.EncodeAll(z.buf.Bytes(), nil)
	_, err := io.Copy(z.writer, bytes.NewReader(compressed))
	return err
}

func (c *compressor) Decompress(r io.Reader) (io.Reader, error) {
	var err error
	var found bool
	var decoder *zstd.Decoder

	// Note: avoid the use of zstd.Decoder.DecodeAll here, since
	// malicious payloads could DoS us with a decompression bomb.

	decoder, found = c.decoderPool.Get().(*zstd.Decoder)
	if !found {
		decoder, err = zstd.NewReader(r, decoderOptions...)
		if err != nil {
			return nil, err
		}
	} else {
		err = decoder.Reset(r)
		if err != nil {
			c.decoderPool.Put(decoder)
			return nil, err
		}
	}

	wrapper := &decoderWrapper{
		decoder: decoder,
		pool:    &c.decoderPool,
	}
	runtime.SetFinalizer(wrapper, func(dw *decoderWrapper) {
		dw.returnToPool()
	})

	return wrapper, nil
}

func (c *compressor) Name() string {
	return Name
}
