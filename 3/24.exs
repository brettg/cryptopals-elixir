use Bitwise

defmodule CryptUtils do
  defmodule PaddingError do
    defexception message: "Invalid pkcs7 Padding"
  end

  ### ECB
  def aes_ecb_encrypt(key, data) do
    aes_ecb_encrypt_raw(key, pkcs7_pad(data, length(key)))
  end
  defp aes_ecb_encrypt_raw(key, data) do
    :crypto.block_encrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
  end

  def aes_ecb_decrypt(key, data) do
    aes_ecb_decrypt_raw(key, data) |> pkcs7_unpad(length(key))
  end
  defp aes_ecb_decrypt_raw(key, data) do
    :crypto.block_decrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
  end

  ### CBC
  def aes_cbc_encrypt(key, iv, data) do
    aes_cbc_encrypt_raw(key, iv, pkcs7_pad(data, length(key)))
  end
  defp aes_cbc_encrypt_raw(_key, _iv, []), do: []
  defp aes_cbc_encrypt_raw(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    encrypted = aes_ecb_encrypt_raw(key, fixed_xor(iv, block))
    encrypted ++ aes_cbc_encrypt_raw(key, encrypted, rest)
  end

  def aes_cbc_decrypt(key, iv, data) do
    aes_cbc_decrypt_raw(key, iv, data) |> pkcs7_unpad(length(key))
  end
  defp aes_cbc_decrypt_raw(_key, _iv, []), do: []
  defp aes_cbc_decrypt_raw(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    decrypted = fixed_xor(aes_ecb_decrypt_raw(key, block), iv)
    decrypted ++ aes_cbc_decrypt_raw(key, block, rest)
  end

  ### CTR
  def aes_ctr_encrypt(key, nonce, data) do
    fixed_xor(data, aes_ctr_keystream(key, nonce, length(data)))
  end
  def aes_ctr_decrypt(key, nonce, ctext) do
    fixed_xor(ctext, aes_ctr_keystream(key, nonce, length(ctext)))
  end
  def aes_ctr_keystream(key, nonce, size) do
    bin_key = IO.iodata_to_binary(key)
    Enum.map(0..div(size, length(key)), fn(n) ->
      count_block = << nonce::little-integer-size(64) >> <> << n::little-integer-size(64) >>
      :crypto.block_encrypt(:aes_ecb, bin_key, count_block) |> :binary.bin_to_list
    end)
    |> List.flatten
  end

  ### PKCS7 Padding
  def pkcs7_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    list ++ pkcs7_padding(blocksize - last_size)
  end

  def pkcs7_unpad(list, blocksize) do
    {most, last} = Enum.split(list, length(list) - blocksize)
    most ++ pkcs7_unpad_block(last)
  end
  defp pkcs7_unpad_block(list) do
    size = length(list)
    num = List.last(list)
    {unpadded, padding} = Enum.split(list, -num)
    if num > 0 and num < (size + 1) and padding == pkcs7_padding(num) do
      unpadded
    else
      raise PaddingError, message: "Invalid pkcs7 Padding! #{length(list)} #{inspect(list)}"
    end
  end

  def pkcs7_padding(n), do: (for _ <- 1..n, do: n)

  ## Utils
  def to_64(list), do: list |> IO.iodata_to_binary |> Base.encode64
  def parse_64(string) do
    string |> Base.decode64!(ignore_whitespace: true) |> :binary.bin_to_list
  end

  def fixed_xor(l1, l2), do: Enum.zip(l1, l2) |> Enum.map(fn({b1, b2}) -> b1 ^^^ b2 end)

  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)
  def rand_lowercase(n), do: (for _ <- 1..n, do: 96 + :rand.uniform(26))

  def const_bytes(0, _), do: []
  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte)

  def columnize([]), do: []
  def columnize(l) do
    heads = heads(l)
    if Enum.empty?(heads), do: [], else: [heads | columnize(tails(l))]
  end
  def tails([]), do: []
  def tails([[] | cdr]), do: tails(cdr)
  def tails([car | cdr]) do
    [tl(car) | tails(cdr)]
  end
  def heads([]), do: []
  def heads([[] | cdr]), do: heads(cdr)
  def heads([car | cdr]) do
    [hd(car) | heads(cdr)]
  end
end

defmodule MT19937 do
  @w 32
  @n 624

  @low_bits 0xFFFFFFFF

  def seed(n) do
    Process.put(:mt19937_idx, @n)
    Process.put(:mt19937_series, gen_series(n))
  end

  def rand do
    if Process.get(:mt19937_idx) >= @n, do: twist

    idx = Process.get(:mt19937_idx)
    num = elem(Process.get(:mt19937_series), idx)
    num = num ^^^ (num >>> 11)
    num = num ^^^ ((num <<< 7) &&& 0x9D2C5680)
    num = num ^^^ ((num <<< 15) &&& 0xEFC60000)
    num = num ^^^ (num >>> 18)

    Process.put(:mt19937_idx, idx + 1)

    num &&& @low_bits
  end

  defp twist do
    new_mt = Enum.reduce(0..(@n - 1), Process.get(:mt19937_series), fn(i, mt) ->
      x = (elem(mt, i) &&& 0x80000000) + (elem(mt, rem(i + 1, @n)) &&& 0x7fffffff)
      xA = x >>> 1
      xA = if rem(x, 2) != 0, do: xA ^^^ 0x9908B0DF, else: xA

      put_elem(mt, i, elem(mt, rem(i + 397, @n)) ^^^ xA)
    end)

    Process.put(:mt19937_series, new_mt)
    Process.put(:mt19937_idx, 0)
  end

  defp gen_series(first), do: List.to_tuple([first | gen_series(first, 1)])
  defp gen_series(_prev, @n), do: []
  defp gen_series(prev, idx) do
    num = @low_bits &&& ((1812433253 * (prev ^^^ (prev >>> 30))) + idx)
    [num | gen_series(num, idx + 1)]
  end
end

defmodule S3Ch24 do
  @key :rand.uniform(0xffff)

  def ency(text) do
    prefix = CryptUtils.rand_lowercase(2 + :rand.uniform(20))
    # IO.inspect prefix
    mt19937_encrypt(@key, prefix ++ text)
  end

  def mt19937_encrypt(key, data) do
    CryptUtils.fixed_xor(data, mt19937_keystream(key, length(data)))
  end
  def mt19937_decrypt(key, ctext) do
    CryptUtils.fixed_xor(ctext, mt19937_keystream(key, length(ctext)))
  end
  def mt19937_keystream(key, size) do
    MT19937.seed(key)
    (for _ <- 0..(div(size, 4)), do: :binary.bin_to_list(<< MT19937.rand::size(32) >>))
    |> List.flatten
  end

  def reverse_temper(num) do
    num
    |> reverse_temper_right(18)
    |> reverse_temper_left(15, 0xEFC60000)
    |> reverse_temper_left(7, 0x9D2C5680)
    |> reverse_temper_right(11)
  end

  def reverse_temper_right(n, shift) do
    bits = Integer.digits(n, 2) |> List.to_tuple
    len = tuple_size(bits)

    Enum.reduce(0..(len - 1), bits, fn(idx, bs) ->
      if idx >= shift do
        put_elem(bs, idx, elem(bs, idx) ^^^ elem(bs, idx - shift))
      else
        bs
      end
    end)
    |> Tuple.to_list
    |> Integer.undigits(2)
  end

  def reverse_temper_left(n, shift, magic) do
    mag_bits = pad_digs(magic, 32)
    bits = pad_digs(n, 32)

    Enum.reduce(31..0, bits, fn(idx, bs) ->
      if idx <= (32 - shift - 1) do
        b = elem(bs, idx)
        orbit = elem(bs, idx + shift)
        mbit = elem(mag_bits, idx)

        put_elem(bs, idx, (orbit &&& mbit) ^^^ b)
      else
        bs
      end
    end)
    |> Tuple.to_list
    |> Integer.undigits(2)
  end

  def pad_digs(n, l) do
    digs = Integer.digits(n, 2)
    pad = if length(digs) < l, do: (for _ <- (0..(l - length(digs) - 1)), do: 0), else: []
    List.to_tuple(pad ++ digs)
  end

  # The instructions were slightly unlear. Was I supposed to encrypt something here or just make a
  # token from the RNG?
  def reset_token do
    MT19937.seed unix_now
    Enum.reduce(0..10, <<>>, fn(_, acc) -> acc <> << MT19937.rand::size(32) >> end)
    |> Base.encode64
  end
  def unix_now, do: DateTime.to_unix(DateTime.utc_now)
end


# key = 10313
# ptext = 'this is a great string of text for testing encryption and decrption'
# ctext = S3Ch24.mt19937_encrypt(key, ptext)
# IO.inspect [ptext, ctext, S3Ch24.mt19937_decrypt(key, ctext)]


input = CryptUtils.const_bytes(14, ?A)
ctext = S3Ch24.ency(input)

prefix_len = length(ctext) - length(input)

first_known_idx = div(prefix_len, 4) + 1
keystream = CryptUtils.fixed_xor(ctext, CryptUtils.const_bytes(length(ctext), ?A))
known_rand = Integer.undigits(Enum.slice(keystream, first_known_idx * 4, 4), 256)

IO.inspect [prefix_len, first_known_idx, known_rand]
found_key = Enum.find 0..0xffff, fn(n) ->
  MT19937.seed(n)
  for _ <- 0..(first_known_idx - 1), do: MT19937.rand
  known_rand == MT19937.rand
end
IO.inspect ['found key', found_key]
IO.inspect S3Ch24.mt19937_decrypt(found_key, ctext)

before = S3Ch24.unix_now
token = S3Ch24.reset_token
rands = CryptUtils.parse_64(token)
        |> Enum.chunk(4)
        |> Enum.map(&(Integer.undigits(&1, 256)))

IO.inspect rands
# Were it something encrypted we could do the same thing, try to decrypt, check char frequency...
IO.inspect Enum.any?(before..S3Ch24.unix_now, fn(t) ->
  MT19937.seed(t)
  rands == (for _ <- 1..length(rands), do: MT19937.rand)
end)
