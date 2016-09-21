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
end

defmodule S3Ch19 do
  @key CryptUtils.rand_bytes(16)
  @nonce 0

  @unsorted File.read!("3/19.txt")
  |> String.split
  |> Enum.map(&CryptUtils.parse_64/1)
  |> Enum.map(&(CryptUtils.aes_ctr_encrypt(@key, @nonce, &1)))

  @ctexts Enum.sort_by(@unsorted, &length/1) |> Enum.reverse
  def ctexts, do: @ctexts

  def guess_single_letter(letter), do: guess_single_letter(letter, ctexts)
  def guess_single_letter(letter, offset) when is_number(offset) do
    guess_single_letter(letter, Enum.drop(ctexts, offset))
  end
  def guess_single_letter(letter, [first | rest]) do
    keystream_guess = Enum.map(first, &(letter ^^^ &1))
    Enum.map(rest, &(CryptUtils.fixed_xor(keystream_guess, &1)))
    |> columnize
    |> likely_solves(keystream_guess)
  end

  def likely_solves(column_list, keystream_guess) do
    column_list
    |> Enum.with_index
    |> Enum.reduce(%{}, fn({col, idx}, map) ->
      if list_score(col) > 3.3 do
        Map.put(map, idx, Enum.at(keystream_guess, idx))
      else
        map
      end
    end)
  end

  def columnize([]), do: []
  def columnize(l) do
    [heads(l) | columnize(tails(l))]
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

  def list_score([]), do: 0
  def list_score(list) do
    (list |> Enum.map(&char_score/1) |> Enum.sum) / length(list)
  end
  def char_score(c) do
    case c do
      x when x in 'aeiou ' -> 5
      x when x in 'dlprst\n' -> 3
      x when x in 97..122 -> 2 # lowercase
      x when x in 65..90 -> 1 # uppercase
      x when x in 48..57 -> 1 # numbers
      x when x < 9 or x in 14..31 or x in 127..255 -> -50
      _ -> -1
    end
  end

  def try_solves(solves) do
    try_keystream for n <- 0..length(hd(ctexts)), do: solves[n] || 0
  end

  def try_keystream(ks) do
    for ctext <- @unsorted do
      # IO.puts '012345679-12345679+12345679*12345679'
      IO.puts CryptUtils.fixed_xor(ks, ctext)
    end
    nil
  end
end

# IO.inspect ['num ctexts', length(S3Ch19.ctexts)]
# IO.inspect ['lengths', Enum.map(S3Ch19.ctexts, &length/1)]

# My approach was going to be that of Ch 20 until I read it too early. So this is arbitrarily not
# (precisely) that.

guesses = ' eaioustrlnbcdfghjklopqvwxyz?.!,;'
solves = Enum.reduce guesses, %{}, fn(char, map) ->
  Enum.reduce(1..30, %{}, fn(n, map) ->
    Map.merge(S3Ch19.guess_single_letter(char, n), map)
  end)
  |> Map.merge(map)
end

IO.inspect solves
# %{11 => 160, 26 => 59, 15 => 248, 20 => 238, 17 => 47, 25 => 153, 13 => 233,
#   0 => 11, 8 => 115, 7 => 88, 1 => 173, 32 => 24, 3 => 103, 6 => 226, 2 => 221,
#   33 => 94, 10 => 3, 9 => 77, 19 => 33, 14 => 93, 5 => 87, 18 => 206, 31 => 235,
#   22 => 224, 29 => 160, 21 => 107, 27 => 107, 24 => 240, 30 => 4, 23 => 208,
#   16 => 251, 4 => 238, 12 => 121}
S3Ch19.try_solves(solves)

IO.puts ''
S3Ch19.try_keystream CryptUtils.fixed_xor('He, too, has been changed in his turn,',
                                          hd(S3Ch19.ctexts))



