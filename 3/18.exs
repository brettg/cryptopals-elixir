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

input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
|> CryptUtils.parse_64

IO.inspect CryptUtils.aes_ctr_decrypt('YELLOW SUBMARINE', 0, input)
