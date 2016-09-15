use Bitwise

defmodule CryptUtils do
  defmodule PaddingError do
    defexception message: "Invalid pkcs7 Padding"
  end

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

  def to_64(list), do: list |> IO.iodata_to_binary |> Base.encode64
  def parse_64(string) do
    string |> Base.decode64!(ignore_whitespace: true) |> :binary.bin_to_list
  end

  def fixed_xor(l1, l2), do: Enum.zip(l1, l2) |> Enum.map(fn({b1, b2}) -> b1 ^^^ b2 end)

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
  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)

  def const_bytes(0, _), do: []
  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte)
end

defmodule S3Ch17 do
  @inputs ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
           "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
           "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
           "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
           "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
           "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
           "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
           "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
           "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
           "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

  @key CryptUtils.rand_bytes(16)
  @iv CryptUtils.rand_bytes(16)

  defp rand_input do
    Enum.at(@inputs, :rand.uniform(length(@inputs) - 1)) |> CryptUtils.parse_64
  end

  def rand_enc, do: enc(rand_input)

  def enc(ptext) do
    {CryptUtils.aes_cbc_encrypt(@key, @iv, ptext), @iv}
  end

  def porc(ctext) do
    try do
      CryptUtils.aes_cbc_decrypt(@key, @iv, ctext)
      true
    rescue
      CryptUtils.PaddingError -> false
    end
  end

  def solve_each do
    Enum.map(@inputs, fn(i) ->
      {ctext, iv} = CryptUtils.parse_64(i) |> enc
      solve(iv, ctext)
    end)
  end

  def solve(iv, ctext) do
    size = length(iv)
    ctext = iv ++ ctext
    block_c = div(length(ctext), size)

    Enum.map(2..block_c, fn(b) ->
      shortened = Enum.slice(ctext, 0, (b) * size)
      solve_last_block(iv, shortened, '')
    end)
    |> List.flatten
    |> CryptUtils.pkcs7_unpad(size)
  end

  def solve_last_block(iv, _ctext, solved) when length(iv) == length(solved), do: solved
  def solve_last_block(iv, ctext, solved) do
    blocks = Enum.chunk(ctext, length(iv))
    prev_block = Enum.at(blocks, -2)

    char = Enum.find 1..0xff, fn(n) ->
      guess = [n] ++ solved
      altered = alter_prev_block(prev_block, guess)
      if altered != prev_block do
        porc(List.replace_at(blocks, -2, altered) |> List.flatten)
      end
    end
    # Assume we have an exact match for the actual padding.
    char = if !char, do: length(solved) + 1, else: char

    solve_last_block(iv, ctext, [char] ++ solved)
  end

  def alter_prev_block(block, guess) do
    size = length(block)
    pad_num = length(guess)
    Enum.with_index(block) |> Enum.map(fn({b, idx}) ->
      if (size - idx) <= pad_num do
        guess_b = Enum.at(guess, pad_num - (size - idx))
        b ^^^ (pad_num ^^^ guess_b)
      else
        b
      end
    end)
  end
end

# These were all broken, mainly because the didn't pad whole blocks when needed...
# IO.inspect CryptUtils.pkcs7_pad('YELLOW SUBMARINE', 16)
# IO.inspect CryptUtils.pkcs7_pad('YELLOW ', 16)
# IO.inspect CryptUtils.pkcs7_unpad('YELLOW SUBMAR\x03\x03\x03', 16)
# IO.inspect CryptUtils.pkcs7_unpad('YELLOW SUBMARINE' ++ (for _ <- 1..16, do: 16), 16)
# IO.inspect CryptUtils.pkcs7_unpad('YELLOW SUBMARINE', 16)

# As such these were quite buggy...
# key = 'FROGGY FROGPANTS'
# iv  = CryptUtils.rand_bytes(16)
# ptext = 'This is the fun plaintext. Not because it\'s plain but because of the implications.'
# ctext = CryptUtils.aes_cbc_encrypt(key, iv, ptext)
# IO.inspect {length(ptext), length(ctext)}
# IO.inspect CryptUtils.aes_cbc_decrypt(key, iv, ctext)
# ctext2 = CryptUtils.aes_ecb_encrypt(key, ptext)
# IO.inspect CryptUtils.aes_ecb_decrypt(key, ctext2)

{enc, iv} = S3Ch17.rand_enc
IO.inspect S3Ch17.porc(enc)
IO.inspect S3Ch17.solve(iv, enc)
IO.inspect S3Ch17.solve_each
