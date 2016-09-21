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

defmodule S3Ch20 do
  @key CryptUtils.rand_bytes(16)
  @nonce 0

  @ctexts File.read!("3/20.txt")
  |> String.split
  |> Enum.map(&CryptUtils.parse_64/1)
  |> Enum.map(&(CryptUtils.aes_ctr_encrypt(@key, @nonce, &1)))

  @min_len Enum.map(@ctexts, &length/1) |> Enum.min
  @truncated Enum.map(@ctexts, &(Enum.slice(&1, 0, @min_len)))

  @columns CryptUtils.columnize(@truncated)

  def ctexts, do: @ctexts
  def columns, do: @columns

  def solve_columns do
    [best_key_byte(hd(columns), &first_char_score/1) | solve_columns(tl(@columns))]
  end
  def solve_columns([]), do: []
  def solve_columns([car | cdr]) do
    [best_key_byte(car) |  solve_columns(cdr)]
  end
  def best_key_byte(col, scorer \\ &char_score/1) do
    column_scores(col, scorer)
    |> Enum.max_by(&(elem(&1, 1)))
    |> elem(0)
  end
  def column_scores(col, scorer \\ &char_score/1) do
    1..0xff
    |> Enum.map(fn(n) ->
      dec = CryptUtils.fixed_xor(col, CryptUtils.const_bytes(length(col), n))
      {n, list_score(dec, scorer)}
    end)
    |> Enum.sort_by(&(-elem(&1, 1)))
  end

  def list_score([], _scorer), do: 0
  def list_score(list, scorer) do
    (list |> Enum.map(scorer) |> Enum.sum) / length(list)
  end

  def first_char_score(c) do
    case c do
      x when x in '\'"1' -> 5
      x when x in 65..90 -> 5 # uppercase
      x when x in 97..122 -> 2 # lowercase
      x when x in 48..57 -> 1 # numbers
      x when x in '.?,!;\'"' -> 1
      x when x < 9 or x in 14..31 or x in 127..255 -> -50 # unprintable
      _ -> -1
    end
  end
  def char_score(c) do
    case c do
      x when x in ' etaoinshrdlu' -> 5
      x when x in 97..122 -> 2 # lowercase
      x when x in 65..90 -> 2 # uppercase
      x when x in 48..57 -> 1 # numbers
      x when x in '.?,!;\'"/' -> 1
      x when x < 9 or x in 14..31 or x in 127..255 -> -50 # unprintable
      _ -> -1
    end
  end

  def try_keystream(ks) do
    for {ctext, idx} <- Enum.with_index(@ctexts) do
      idx = idx |> Integer.to_string |> String.rjust(3, ?\s)
      IO.puts "#{idx}: #{CryptUtils.fixed_xor(ks, ctext)}"
    end
  end
end

# col = Enum.at(S3Ch20.columns, 21)
# IO.inspect col
# scores = S3Ch20.column_scores(col)
# for {b, s} <- Enum.slice(scores, 0, 10) do
#   IO.inspect {b, s}
#   IO.inspect CryptUtils.fixed_xor(col, CryptUtils.const_bytes(length(col), b))
# end

keystream_guess = S3Ch20.solve_columns
S3Ch20.try_keystream(keystream_guess)

# IO.inspect Enum.map(S3Ch20.ctexts, &length/1) |> Enum.with_index |> Enum.max_by(&(elem(&1, 0)))

IO.puts ''

# ... googling for lyrics to get untruncated part...
googled_line = 'You want to hear some sounds that not only pounds but please your eardrums;' ++
               ' / I sit back and observe the whole scenery'
googled_keystream = CryptUtils.fixed_xor(Enum.at(S3Ch20.ctexts, 26), googled_line)
S3Ch20.try_keystream(googled_keystream)
