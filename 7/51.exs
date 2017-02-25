
defmodule UtilsFromTheCrypt do
  def pkcs7_pad(binary, blocksize) when is_binary(binary) do
    pkcs7_pad(:binary.bin_to_list(binary), blocksize)
  end
  def pkcs7_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    list ++ pkcs7_padding(blocksize - last_size)
  end

  def pkcs7_padding(n), do: (for _ <- 1..n, do: n)
end

defmodule Oracle do
  @sessionid "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

  def len(msg) do
    format(msg)
    |> :zlib.gzip
    |> stream_encrypt
    |> byte_size
  end

  def len_bc(msg) do
    format(msg)
    |> :zlib.gzip
    |> block_encrypt
    |> byte_size
  end

  def check(sid) when is_list(sid), do: IO.iodata_to_binary(sid) |> check
  def check(sid), do: sid == @sessionid

  defp format(msg) when is_list(msg), do: IO.iodata_to_binary(msg) |> format
  defp format(msg) do
    "POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=#{@sessionid}
Content-Length: #{byte_size(msg)}

#{msg}"
    |> String.replace("\n", "\r\n")
  end

  defp stream_encrypt(msg) do
    :crypto.stream_init(:aes_ctr, rand_bytes(16), rand_bytes_bin(16))
    |> :crypto.stream_encrypt(msg)
    |> elem(1)
  end

  defp block_encrypt(msg) do
    padded = UtilsFromTheCrypt.pkcs7_pad(msg, 16)
    :crypto.block_encrypt(:aes_cbc, rand_bytes(16), rand_bytes_bin(16), padded)
  end

  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)
  def rand_bytes_bin(n), do: rand_bytes(n) |> IO.iodata_to_binary
end

defmodule Attack do
  @alphabet 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r'
  @padabet '()*&^%$#@!~`<>[]'
  @pairs for a <- @alphabet, b <- @alphabet, do: [a, b]

  def find_sid, do: find_sid('sessionid=', '')
  def find_sid(prefix, found) do
    case next_char(prefix ++ found) do
      c when c in '=\r' -> found ++ [c]
      nil -> found
      c -> find_sid(prefix, found ++ [c])
    end
  end

  def find_sid_bc, do: find_sid_bc('sessionid=', '')
  def find_sid_bc(prefix, found) do
    case next_char_bc(pad_for_boundary(prefix ++ found) ++ prefix ++ found) do
      c when c in '=\r' -> found ++ [c]
      nil -> found
      c -> find_sid_bc(prefix, found ++ [c])
    end
  end

  def pad_for_boundary(s), do: padlen_for_boundary(s, Oracle.len_bc(s), 1) |> pad_chars

  def padlen_for_boundary(s, base, n) do
    if Oracle.len_bc(pad_chars(n) ++ s) > base do
      if n < 3, do: n + 14, else: n - 2
    else
      padlen_for_boundary(s, base, n + 1)
    end
  end

  def pad_chars(n), do: Enum.slice(@padabet, 0..(n - 1))

  def next_char(base), do: next_char_for(base, &Oracle.len/1)

  def next_char_bc(base), do: next_char_for(base, &Oracle.len_bc/1)

  def next_char_for(base, oracle_fn) do
    Enum.map(@pairs, &({&1, oracle_fn.(base ++ &1)}))
    |> Enum.sort_by(&(elem(&1, 1)))
    |> hd
    |> elem(0)
    |> hd
  end

end

found = Attack.find_sid
IO.inspect ['For Stream Cipher:', found, Oracle.check(found)]

found_bc = Attack.find_sid_bc
IO.inspect ['For Block Cipher:', found_bc, Oracle.check(found_bc)]
