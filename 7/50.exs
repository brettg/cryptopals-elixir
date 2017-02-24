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

  def aes_cbc_mac(key, iv, data) do
    aes_cbc_encrypt(key, iv, data)
    |> Enum.chunk(length(key))
    |> List.last
  end

  ### PKCS7 Padding
  def pkcs7_pad(binary, blocksize) when is_binary(binary) do
    pkcs7_pad(:binary.bin_to_list(binary), blocksize)
  end
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
      list
    end
  end

  def pkcs7_padding(n), do: (for _ <- 1..n, do: n)

  ## Utils
  def to_64(list), do: list |> IO.iodata_to_binary |> Base.encode64
  def parse_64(string) do
    string |> Base.decode64!(ignore_whitespace: true) |> :binary.bin_to_list
  end
  def to_hex(list), do: list |> IO.iodata_to_binary |> Base.encode16(case: :lower)

  def fixed_xor(l1, l2), do: Enum.zip(l1, l2) |> Enum.map(fn({b1, b2}) -> b1 ^^^ b2 end)

  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)
  def rand_lowercase(n), do: (for _ <- 1..n, do: 96 + :rand.uniform(26))

  def const_bytes(0, _), do: []
  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte)

  def blocks(v, size \\ 16)
  def blocks(b, size) when is_binary(b), do: :binary.bin_to_list(b) |> blocks(size)
  def blocks(l, size), do: Enum.chunk(l, size, size, [])
end

defmodule S7Ch50 do

  def find_printable(key, iv, prefix, xor_block, n \\ 0) do
    block = rand_block
    enc = CryptUtils.aes_cbc_encrypt(key, iv, prefix ++ block)
    final_block_enc = Enum.chunk(enc, 16) |> Enum.at(-2)

    if rem(n, 100000) == 0, do: IO.inspect n

    result = CryptUtils.fixed_xor(xor_block, final_block_enc)

    if works?(block) && works?(result) do
      IO.inspect [block, result]
      block
    else
      find_printable(key, iv, prefix, xor_block, n + 1)
    end
  end

  def works?(l), do: Enum.all?(l, &(&1 < 128 && &1 != 13 && &1 != 14))

  def rand_block, do: for _ <- 1..16, do: :crypto.rand_uniform(1, 127)

  def n_to_block(n) do
    Base.encode16(<<n>>) |> String.pad_leading(16, " ") |> :binary.bin_to_list
  end
end

key = 'YELLOW SUBMARINE'
iv = CryptUtils.const_bytes(16, 0)
msg = "alert('MZA who was that?');\n"
target_hash = "296b8d7cb78a243dda4d0a61d33bbdd1"

payload =  'alert("Ayo, the Wu is back!");//'
[msg_first | msg_rest] = :binary.bin_to_list(msg) |> CryptUtils.blocks

payload = payload ++ S7Ch50.find_printable(key, iv, payload, msg_first)

pl_enc = CryptUtils.aes_cbc_encrypt(key, iv, payload)
pl_final_block_enc = Enum.chunk(pl_enc, 16) |> Enum.at(-2)

new_msg = payload ++
          CryptUtils.fixed_xor(msg_first, pl_final_block_enc) ++
          List.flatten(msg_rest)

IO.inspect length(new_msg)
IO.inspect CryptUtils.blocks(new_msg)
IO.inspect [
  CryptUtils.aes_cbc_mac(key, iv, new_msg),
  CryptUtils.aes_cbc_mac(key, iv, new_msg) |> CryptUtils.to_hex,
  CryptUtils.aes_cbc_mac(key, iv, new_msg) |> CryptUtils.to_hex == target_hash
]

IO.inspect File.write("7/50.js", new_msg)
