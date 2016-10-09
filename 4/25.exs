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

defmodule S4Ch25 do
  @orig_ctext "1/7.txt"
  |> File.read!
  |> Base.decode64!(ignore: :whitespace)
  |> :binary.bin_to_list
  @ptext CryptUtils.aes_ecb_decrypt('YELLOW SUBMARINE', @orig_ctext)

  @key CryptUtils.rand_bytes(16)
  @nonce 10
  @ctext CryptUtils.aes_ctr_encrypt(@key, @nonce, @ptext)

  def ctext, do: @ctext

  def edit(ctext, offset, newtext) do
    ptext = CryptUtils.aes_ctr_decrypt(@key, @nonce, ctext)
    new_ptext = list_overwrite(ptext, offset, newtext)
    CryptUtils.aes_ctr_encrypt(@key, @nonce, new_ptext)
  end

  # Overwrite from offset forward w/o going past length of original.
  def list_overwrite(l, offset, new_l) do
    after_offset = offset + length(new_l) - 1
    if after_offset < length(l) - 1 do
      Enum.slice(l, 0, offset - 1) ++ new_l ++ Enum.slice(l, after_offset, length(l) - after_offset)
    else
      replace_part = Enum.slice(new_l, 0, length(l) - offset + 1)
      if offset > 0, do: Enum.slice(l, 0, offset - 1) ++ replace_part, else: replace_part
    end
  end
end

# s = 'This is about cats.'
# IO.inspect '0123456789012356789'
# IO.inspect s
# IO.inspect S4Ch25.list_overwrite(s, 15, 'r')
# IO.inspect S4Ch25.list_overwrite(s, 15, 'rumba')
# IO.inspect S4Ch25.list_overwrite(s, 15, 'freakss!!!')
# IO.inspect S4Ch25.list_overwrite(s, 0,  'aaaaaaaaaaaaaaaaaaa')

ctext = S4Ch25.ctext
the_as = CryptUtils.const_bytes(length(ctext), ?A)
new_ctext = S4Ch25.edit(ctext, 0, the_as)
keystream = CryptUtils.fixed_xor(the_as, new_ctext)
decrypted = CryptUtils.fixed_xor(keystream, ctext)

IO.inspect ctext
IO.inspect new_ctext
IO.inspect keystream
IO.puts decrypted
